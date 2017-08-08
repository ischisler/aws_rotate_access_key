#!/usr/bin/python

import os
import subprocess
import time
import progressbar
import sys
import getopt
from sys import argv

# Global Variables
iam_user = ""
aws_key_file = ""
aws_profile = "default"
json_output_file = ""
s3_test_file = ""
csv_output_file = ""
new_key = ""
no_key = False
disable_old = False
replace_local_key = False
new_access_key_id = ""
new_secret_key = ""
existing_key_id = ""


def print_help():
    print "usage: " + argv[0] + " [options....] "
    print "options:"
    print "-u, --user       The IAM user whose key you want to rotate. (REQUIRED)"
    print "-p, --profile    The AWS profile you want to use if you have multiple access key profiles,"
    print "                 otherwise will use [default]"
    print "-u, --help       Prints this help message"
    quit()


def query_yes_no(question, default="no"):
    # Yes or no question function
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def get_access_key():
    global replace_local_key
    cred_file = os.path.expanduser("~")
    cred_file += "/.aws/credentials"
    r_cred = open(cred_file, 'r')
    key_found = False
    for row in r_cred:
        # If profile key is found print access key id and secret key for verification
        if aws_profile in row:
            print "USING THE FOLLOWING LOCAL KEY FOR " + aws_profile + " PROFILE:"
            print("aws_access_key_id = " + next(r_cred, '').strip())
            # query_yes_no("Do you want to replace this local key with new key we create?")
            replace_local_key = query_yes_no("Do you want to replace this local key with the new one we create?")
            key_found = True
            break
        elif row == '\n':
            continue
    # If no access key is found quit
    if key_found is False:
        print "No local access key found for profile: " + aws_profile
        print "Exiting......."
        exit(-1)


def check_num_of_keys():
    global no_key
    print "Verifying current number of keys for user: " + iam_user + " ..........."
    bar = progressbar.ProgressBar()
    for i in bar(range(100)):
        time.sleep(0.04)
    num_keys = subprocess.check_output("aws iam list-access-keys --user-name " + iam_user + " --profile " + aws_profile + " --output text | wc -l", shell=True)
    if num_keys.strip() == "0":
        print "There was no keys found for user " + iam_user + ". We will create a new one."
        no_key = True
    elif num_keys.strip() == "2":
        print "There are already two keys in-use for this user (which is the max per IAM user). Unable to rotate key."
        exit(-1)


def create_new_key():
    global new_secret_key, new_access_key_id, new_key
    print "Creating new access key in aws .........."
    bar = progressbar.ProgressBar()
    new_key = subprocess.check_output("aws iam create-access-key --user-name " + iam_user + " --profile " + aws_profile + " --output text", shell=True)
    for i in bar(range(100)):
        time.sleep(0.05)
    print "Access keys created for user " + iam_user
    new_key_split = new_key.split()
    new_access_key_id = new_key_split[1]
    new_secret_key = new_key_split[3]
    #for i in new_key:
    #    new_access_key_id = new_key.strip()
    #    new_secret_key = next(new_key, '').strip()
    #print "New access key ID: " + new_access_key_id
    #print "New secret key: " + new_secret_key

def test_key_access():
    #START TOMORROW
    global new_secret_key, new_access_key_id, new_key, disable_old, existing_key_id
    print "NEW ACCESS KEY ID: " + new_access_key_id
    print "NEW SECRET KEY: " + new_secret_key
    print "Verifying new access key is in security credentials for user: " + iam_user
    bar = progressbar.ProgressBar()
    for i in bar(range(100)):
        time.sleep(0.05)
    current_keys = subprocess.check_output("aws iam list-access-keys --user " + iam_user + " --profile " + aws_profile + " --output text", shell=True)
    current_keys_split = current_keys.split()
    num_of_aws_keys = len(current_keys_split)
    if num_of_aws_keys > 5:
        if new_access_key_id.strip() == current_keys_split[1].strip():
            print "SUCCESS!"
            print "Access key verified!!"
            existing_key_id = current_keys_split[6].strip()
            disable_old = True
        elif new_access_key_id.strip() == current_keys_split[6].strip():
            print "SUCCESS!"
            print "Access key verified!!"
            existing_key_id = current_keys_split[1].strip()
            disable_old = True
        else:
            print new_access_key_id.strip()
            print current_keys_split[6].strip()
            print current_keys_split[1].strip()
            print "Error in num_of_aws_keys if statement"
            print "Something went wrong, the new access key was not listed in aws for user: " + iam_user
            exit(-1)
    else:
        if new_access_key_id.strip() == current_keys_split[1].strip():
            print "SUCCESS!"
            print "Access key verified!!"
        else:
            print new_access_key_id.strip()
            print current_keys_split[1].strip()
            print "Error in new_access_key_id.strip() if statement"
            print "Something went wrong, the new access key was not listed in aws for user: " + iam_user
            exit(-1)

def disable_old_key():
    print "Deactivating old key......."
    bar = progressbar.ProgressBar()
    for i in bar(range(100)):
        time.sleep(0.03)
    try:
        subprocess.call("aws iam update-access-key --user-name " + iam_user + " --access-key-id " + existing_key_id + " --profile " + aws_profile + " --status Inactive", shell=True)
    except subprocess.CalledProcessError:
        print "An error occured disabling old key, please disable through the console key id: " + existing_key_id


def config_new_key():
    print "Making new key the default for profile: " + aws_profile
    bar = progressbar.ProgressBar()
    for i in bar(range(100)):
        time.sleep(0.03)
    try:
        subprocess.call("aws configure --profile " + aws_profile + " set aws_access_key_id " + new_access_key_id, shell=True)
        subprocess.call("aws configure --profile " + aws_profile + " set aws_secret_access_key " + new_secret_key, shell=True)
    except subprocess.CalledProcessError:
        print "An error occured configuring your new key, please manually enter new creds into ~/.aws/credentials file"
        print "[" + aws_profile + "]"
        print "aws_access_key_id = " + new_access_key_id
        print "aws_secret_access_key = " + new_secret_key

if len(argv) < 2:
    # Print help if only script is called.
    print_help()

try:
    opts, args = getopt.getopt(argv[1:], "u:p:a:s:j:c:h", ["user=", "profile=", "aws-key-file=", "s3-test-file=", "json=", "csv-key-file=", "help"])
except getopt.GetoptError:
    print_help()
    quit()


for opt, arg in opts:
    if opt in ("-u", "--user"):
        iam_user = arg
    elif opt in ("-p", "--profile"):
        aws_profile = arg
    elif opt in ("-a", "--aws-key-file"):
        aws_key_file = arg
    elif opt in ("-s", "--s3-test-file"):
        s3_test_file = arg
    elif opt in ("-j", "--json"):
        json_output_file = arg
    elif opt in ("-c", "--csv-key-file"):
        csv_output_file = arg
    elif opt in ("-h", "--help"):
        print_help()

#print iam_user
# Make sure iam_user is supplied
if not iam_user:
    print "AWS Username REQUIRED!\n\n"
    print_help()

# Check current local access keys for user running program
get_access_key()

# Check AWS to see if they already have the max number of keys
check_num_of_keys()

# Create new key in AWS
create_new_key()

# Ensure new key is applied to the user
test_key_access()

if disable_old == True:
    # If user did not have previous key we will not disable_old in the case of a new user setup.
    disable_old_key()

if replace_local_key == True:
    config_new_key()
