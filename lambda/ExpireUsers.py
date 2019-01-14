import boto3
import csv
import datetime
import dateutil.parser
import json
import os
import sys
from time import sleep
from botocore.exceptions import ClientError
from require_mfa import process_CreateLoginProfile, process_DeleteLoginProfile, process_EnableMFADevice, \
    process_DeactivateMFADevice

# These should be passed in via Lambda Environment Variables
try:
    BLACKHOLE_GROUPNAME = os.environ['BLACKHOLE_GROUPNAME']
    ACTION_TOPIC_ARN = os.environ['ACTION_TOPIC_ARN']
    GRACE_PERIOD = int(os.environ['GRACE_PERIOD'])
    DISABLE_USERS = os.environ['DISABLE_USERS']
    SEND_EMAIL = os.environ['SEND_EMAIL']
except KeyError as e:
    print("Key Error: " + str(e))
    sys.exit(1)

# Define a Global String to be the report output sent to ACTION_TOPIC_ARN
ACTION_SUMMARY = ''
EXPLANATION_FOOTER = ''
EXPLANATION_HEADER = ''
FROM_ADDRESS = 'secureblueprint@kudelskisecurity.com'
REPORT_SUMMARY = ''
print('Loading function')

if DISABLE_USERS == "true":
    expired_message = "\n\tYour Password is {} days post expiration. You will be forced to reset it on your next login. "
    key_expired_message = "\n\tYour AccessKey ID {} is {} days post expiration. It has been deactivated. "
else:
    expired_message = "\n\tYour Password is {} days post expiration. You must change your password or risk losing access. "
    key_expired_message = "\n\tYour AccessKey ID {} is {} days post expiration. You must rotate this key or it will be deactivated. "

key_warn_message = "\n\tYour AccessKey ID {} is {} days from expiration. You must rotate this key or it will be deactivated. "
password_warn_message = "\n\tYour Password will expire in {} days"

email_subject = "Credential Expiration Notice From AWS Account: {}"


def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, sort_keys=True))
    iam_client = boto3.client('iam')

    try:
        if event['source'] == "aws.iam":
            process_IAMEvent(event, context, iam_client)
        else:
            process_UsersCron(iam_client)
    except KeyError as e:
        # Probably called as a test event with out a source. This is what we want to do here.
        process_UsersCron(iam_client)
    return


def process_UsersCron(iam_client):
    global ACTION_SUMMARY  # This is what we send to the admins
    global REPORT_SUMMARY
    max_age = get_max_password_age(iam_client)
    account_name = iam_client.list_account_aliases()['AccountAliases'][0]
    credential_report = get_credential_report(iam_client)

    # Iterate over the credential report, use the report to determine password expiration
    # Then query for access keys, and use the key creation data to determine key expiration
    for row in credential_report:
        if row['password_enabled'] != "true":
            continue  # Skip IAM Users without passwords, they are service accounts

        if 'vault' in row['user']:
            continue

        message = ""  # This is what we send to the user
        # Process MFA Devices
        process_mfa_devices(row['user'], iam_client)
        # Process their password
        password_expires = days_till_expire(row['password_last_changed'], max_age)
        if password_expires <= 0:
            REPORT_SUMMARY = REPORT_SUMMARY + "\n{}'s Password expired {} days ago".format(row['user'],
                                                                                           password_expires * -1)
            message = message + expired_message.format(password_expires * -1)
            #if not is_user_blackholed(row['user'], iam_client):
                # add_user_to_blackhole(row['user'], iam_client)
            if not password_reset_required(row['user'], iam_client):
                force_password_reset(row['user'], iam_client)
        elif password_expires < GRACE_PERIOD:
            message = message + password_warn_message.format(password_expires)
            REPORT_SUMMARY = REPORT_SUMMARY + "\n{}'s Password Will expire in {} days".format(row['user'],
                                                                                            password_expires)
        if password_expires == max_age:
            remove_user_from_blackhole(row['user'], iam_client)
            REPORT_SUMMARY = REPORT_SUMMARY + "\n{}'s password has been updated".format(row['user'])

        try:
            # Process their Access Keys
            response = iam_client.list_access_keys(UserName=row['user'])
            for key in response['AccessKeyMetadata']:
                if key['Status'] == "Inactive":
                    continue
                key_expires = days_till_expire(key['CreateDate'], max_age)
                if key_expires <= 0:
                    message = message + key_expired_message.format(key['AccessKeyId'], key_expires * -1)
                    disable_users_key(key['AccessKeyId'], row['user'], iam_client)
                    REPORT_SUMMARY = REPORT_SUMMARY + "\n{}'s Key {} expired {} days ago ".format(row['user'],
                                                                                                   key['AccessKeyId'],
                                                                                                   key_expires * -1)
                elif key_expires < GRACE_PERIOD:
                    message = message + key_warn_message.format(key['AccessKeyId'], key_expires)
                    REPORT_SUMMARY = REPORT_SUMMARY + "\n{}'s Key {} will expire {} days from now ".format(row['user'],
                                                                                                            key['AccessKeyId'],
                                                                                                            key_expires)
        except ClientError as e:
            print(str(e))
            continue

        # Email user if necessary
        if message != "":
            email_user(row['user'], message, account_name, iam_client)

    # All Done. Send a summary to the ACTION_TOPIC_ARN, and print one out for the Lambda Logs
    print("Action Summary:" + ACTION_SUMMARY)
    print("Report Summary: " + REPORT_SUMMARY)
    if ACTION_SUMMARY != "":
        send_summary()
    # if REPORT_SUMMARY != "": email_user(FROM_ADDRESS, REPORT_SUMMARY, account_name)
    return


def is_user_blackholed(username, iam_client):
    # 0 for not-expired, 1 for expired
    try:
        response = iam_client.list_groups_for_user(UserName=username)
    except ClientError as e:
        return 1

    for group in response['Groups']:
        if group['GroupName'] == BLACKHOLE_GROUPNAME:
            return 1
    return 0


def password_reset_required(user, iam_client):
    login_profile = iam_client.get_login_profile(UserName=user)
    return login_profile['LoginProfile']['PasswordResetRequired']


def email_user(email, message, account_name, iam_client):
    global ACTION_SUMMARY  # This is what we send to the admins
    if SEND_EMAIL != "true":
        return  # Abort if we're not supposed to send email
    if message == "":
        return  # Don't send an empty message
    client = boto3.client('ses')
    body = EXPLANATION_HEADER + "\n" + message + "\n\n" + EXPLANATION_FOOTER
    email = get_user_email_from_tag(iam_client=iam_client, user=email)
    if email:
        try:
            response = client.send_email(
                Source=FROM_ADDRESS,
                Destination={'ToAddresses': [email]},
                Message={
                    'Subject': {'Data': email_subject.format(account_name)},
                    'Body': {'Text': {'Data': body}}
                }
            )
            ACTION_SUMMARY = ACTION_SUMMARY + "\nEmail Sent to {}".format(email)
            return
        except ClientError as e:
            print("Failed to send message to {}: {}".format(email, e.message))
            ACTION_SUMMARY = ACTION_SUMMARY + "\nERROR: Message to {} was rejected: {}".format(email, e.message)


def days_till_expire(last_changed, max_age):
    # Ok - So last_changed can either be a string to parse or already a datetime object.
    # Handle these accordingly
    if type(last_changed) is str:
        last_changed_date = dateutil.parser.parse(last_changed).date()
    elif type(last_changed) is datetime.datetime:
        last_changed_date = last_changed.date()
    else:
        # print("last_changed", last_changed)
        # print(type(last_changed))
        return -99999
    expires = (last_changed_date + datetime.timedelta(max_age)) - datetime.date.today()
    return (expires.days)


# Request the credential report, download and parse the CSV.
def get_credential_report(iam_client):
    resp1 = iam_client.generate_credential_report()
    if resp1['State'] == 'COMPLETE':
        try:
            response = iam_client.get_credential_report()
            credential_report_csv = response['Content'].decode('utf-8')
            # print(credential_report_csv)
            reader = csv.DictReader(credential_report_csv.splitlines())
            # print(reader.fieldnames)
            credential_report = []
            for row in reader:
                credential_report.append(row)
            return credential_report
        except ClientError as e:
            print("Unknown error getting Report: " + e.message)
    else:
        sleep(2)
        return get_credential_report(iam_client)


def get_user_email_from_tag(iam_client, user):
    user_tags = iam_client.list_user_tags(UserName=user)
    email_tag = [tag for tag in user_tags['Tags'] if tag['Key'] == 'email']
    if email_tag:
        return email_tag[0]['Value']


# Query the account's password policy for the password age. Return that number of days
def get_max_password_age(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        return response['PasswordPolicy']['MaxPasswordAge']
    except ClientError as e:
        print("Unexpected error in get_max_password_age: %s" + e.message)


def process_IAMEvent(event, context, iam_client):
    api_call = event['detail']['eventName']
    if api_call == "CreateLoginProfile":
        process_CreateLoginProfile(event, context)
        return 0
    elif api_call == "EnableMFADevice":
        process_EnableMFADevice(event, context)
        return 0
    elif api_call == "DeactivateMFADevice":
        process_DeactivateMFADevice(event, context)
        return 0
    elif api_call == "DeleteLoginProfile":
        process_DeleteLoginProfile(event, context)
        return 0
    else:
        raise Exception("Invalid API Call: " + api_call)


# Add the user to the group that only allows them to reset their password
def add_user_to_blackhole(username, iam_client):
    if DISABLE_USERS != "true":
        return
    global ACTION_SUMMARY
    ACTION_SUMMARY = ACTION_SUMMARY + "\nAdding {} to Blackhole Group".format(username)
    response = iam_client.add_user_to_group(
        GroupName=os.environ['BLACKHOLE_GROUPNAME'],
        UserName=username
    )
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        handle_error("Adding User to Blackhole Group", username, response['ResponseMetadata'])
    else:
        return 0


def force_password_reset(username, iam_client):
    if DISABLE_USERS != "true":
        return
    global ACTION_SUMMARY
    ACTION_SUMMARY = ACTION_SUMMARY + "\nForcing {} to reset password on next login".format(username)
    response = iam_client.update_login_profile(UserName=username, PasswordResetRequired=True)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        handle_error("Forced Password reset for", username, response['ResponseMetadata'])
    else:
        return True


# Turn off the specified user's key by setting it to inactive.
def disable_users_key(AccessKeyId, UserName, iam_client):
    if DISABLE_USERS != "true": return
    global ACTION_SUMMARY
    ACTION_SUMMARY = ACTION_SUMMARY + "\nDisabling AccessKeyId {} for user {}".format(AccessKeyId, UserName)
    response = iam_client.update_access_key(
        UserName=UserName,
        AccessKeyId=AccessKeyId,
        Status='Inactive'
    )
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        handle_error("Adding User to Blackhole Group", UserName, response['ResponseMetadata'])
    else:
        return 0


# Not used, but would remove the user from the blackhole group once they did change their password
def remove_user_from_blackhole(username, iam_client):
    response = iam_client.remove_user_from_group(
        GroupName=os.environ['BLACKHOLE_GROUPNAME'],
        UserName=username
    )
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        handle_error("Removing User from Blackhole Group", username, response['ResponseMetadata'])
    else:
        return 0


def process_mfa_devices(user, iam_client):
    global REPORT_SUMMARY
    mfa_response = iam_client.list_mfa_devices(UserName=user)
    mfa_devices = mfa_response['MFADevices']
    if len(mfa_devices) == 0:
        REPORT_SUMMARY = REPORT_SUMMARY + '\n{} has 0 MFA Devices'.format(user)
        if not is_user_blackholed(user, iam_client):
            add_user_to_blackhole(user, iam_client)


def handle_error(action, username, ResponseMetadata):
    raise Exception("ERROR" + action + " User: " + username + " Details: " + ResponseMetadata)


# Send the Summary of actions taken to the SNS topic
def send_summary():
    global ACTION_SUMMARY
    client = boto3.client('sns')

    message = "The following Actions were taken by the Expire Users Script at {}: ".format(
        datetime.datetime.now()) + ACTION_SUMMARY

    response = client.publish(
        TopicArn=ACTION_TOPIC_ARN,
        Message=message,
        Subject="Expire Users Report for {}".format(datetime.date.today())
    )
