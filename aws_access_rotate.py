import boto3
import os
import sys
from slack_webhook import Slack
import json
from datetime import datetime, timedelta
import logging
import base64
# require variable
# SLACK_TOKEN
# SNS_TOPIC
# SERVICE_ACCOUNT #list
###################################################
######This function get user list ###############
##################################################

def get_users(exclude_users=[]):
    client = boto3.client('iam')
    users = client.list_users()
    if not users["Users"]:
        print("No users Found")
        return sys.exit(0)
    users_list = []
    for user in users["Users"]:
        users_list.append(user["UserName"])
    excluded_user = set(users_list).intersection(exclude_users)
    excluded_user_list = list(excluded_user)
    for excluded in excluded_user_list:
        users_list.remove(excluded)
    return users_list
##################################################################
#END#
##################################################################
####
###########################################################
#######This function get user access key age###############
###########################################################
def get_access_key_age(user):
    client = boto3.client('iam')
    if not user:
        print("user is empty")
        sys.exit(0)
    get_users = client.list_access_keys(UserName=user)
    dic_data = get_users["AccessKeyMetadata"]
    if not dic_data:
        print(f"user: {user} has no access key :get_access_key_age function")
    if dic_data:
        user_key_created_at = dic_data[0]['CreateDate']
        user_key_created_at = user_key_created_at.date()
        user_key_status = dic_data[0]['Status']
        today = datetime.now().date()
        user_key_age = today - user_key_created_at
        user_key_age = user_key_age.days
        return {"key_age": user_key_age, "key_status": user_key_status}
#########################################################################
####END############
#########################################################################
#############################################################################################
#############This function return a banlist of user depending of the days specifield##########
###############################################################################################
def get_ban_users(users_list, days):
    ban_user = []
    ####check if list is not empty####
    if not users_list:
        print("no users found in get_ban_users function")
        sys.exit(0)
    ########## end of list check######
    # filtering the user with no access key
    for list in users_list:
        data = get_access_key_age(list)
        if data == None:
            users_list.remove(list)
    # end of filtering user with no access key
    for users in users_list:
        user_data = get_access_key_age(users)
        if user_data["key_age"] > days and user_data["key_status"] == "Active":
            ban_user.append(users)
    if not ban_user:
        return []
    return ban_user
#################################################
###########initiatelizingfunction################
#################################################
#############decryting_kms_encrypted_url##########
def decrypt_url(url):
    if not url:
        print("no url found")
        sys.exit(0)
    try:
        aws_region = os.environ['AWS_REGION']
    except KeyError as error:
        print(f"Set{error}")
        logging.error(f"Set{error}")
        sys.exit(0)
    try:
        kms = boto3.client('kms', region_name=aws_region)
        decrypted_text = kms.decrypt(CiphertextBlob=base64.b64decode(url))['Plaintext']
        return decrypted_text.decode()
    except Exception as error:
        print(f"decrypt url function error: {error}")
        logging.exception("decryption failed")

##################end##############################
###############################################################
############This function get user access key_id###############
###############################################################
def get_access_key_id(user_info):
    if not user_info:
        print("no user info found in get_access_key_id function")
        sys.exit(0)
    client = boto3.client('iam')
    get_users = client.list_access_keys(UserName=user_info)
    dic_data = get_users["AccessKeyMetadata"]
    user_key = dic_data[0]['AccessKeyId']
    user = dic_data[0]['UserName']
    return {"user": user, "user_key": user_key}
###########################################################
####################END####################################
###########################################################
###########################################################
##########Function to delete users from banlist############
###########################################################
def delete_ban_user_key(ban_user_list):
    if not ban_user_list:
        print("list is empty in delete_ban_user_key function")
        sys.exit(0)
    client = boto3.client('iam')
    for users in ban_user_list:
        # print(users)
        key_id = get_access_key_id(users)
        response = client.delete_access_key(UserName=users, AccessKeyId=key_id['user_key'])
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        print("Bad response from IAM client when deleting access key")
        logging.error("Bad response from IAM client when deleting access key")
        logging.error(response)
        return False
    logging.info(response)
    return True
##############################################
#######function to send sns to users #########
##############################################
def send_sns(message, topic_arn):

    if not topic_arn:
        logging.error("please set SNS_TOPIC using your env, variable is required")
        sys.exit(0)
    try:
        sns_client = boto3.client('sns')
    except NameError as error:
        logging(f"send sns function error: {error}")

    response = sns_client.publish(
        TargetArn=topic_arn,
        Message=message,
        Subject="SHARED-SERVICES-AWS-KEY-ROTATION",
        MessageStructure='string')
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        logging.error("Bad response from SNS client when publishing message")
        logging.error(response)
        return False
    logging.info(response)
    return True


def lambda_function(event, context):
    service_account = os.getenv("SERVICE_ACCOUNT")
    all_user = get_users(exclude_users=[service_account])
    ban_list = get_ban_users(all_user, 90)
    email_list = get_ban_users(all_user, 80)
    #########slack########################
    ## get encrypted url from env
    slack_url_encrypted = os.getenv('SLACK_TOKEN')
    if not slack_url_encrypted:
        print("url is empty")
    ###decrpting slack token #########
    slack_url = decrypt_url(slack_url_encrypted)
    slack_message = "  Hello Team, \n \n Please rotate your access before 10day elapses, acesss keys created 90 day ago will be deleted.\n \n Affected-Users-List: {user}  \n \n King Regards \n \n Shared Services User-Acess-key Bots :)" .format(user = email_list)
    if email_list:
        slack = Slack(url=slack_url)
        slack.post(text=slack_message)

    sns_arm = os.getenv('SNS_TOPIC')
    if not sns_arm:
        print("sns topic_arn not found")
    if email_list:
        send_sns(slack_message, sns_arm)
    if ban_list:
        delete_user_ban_list = delete_ban_user_key(ban_list)
        logging.info(f"users deleted: {ban_list}")
        if delete_user_ban_list:
            slack_del = Slack(url=slack_url)
            deleted_message = f"Users {ban_list} access_keys has been deleted because it was 90 days old."
            slack_del.post(text=deleted_message)
    return "access key rotation completed"

