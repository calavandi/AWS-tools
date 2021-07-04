#!/bin/env python3
import boto3
from botocore.exceptions import ClientError
from requests import request
from os.path import expanduser
import argparse

def add_ip_addr(api_keys, security_group, region="ap-south-1"):
    try:
        ec2 = boto3.client('ec2', region, aws_access_key_id = api_keys[0], aws_secret_access_key = api_keys[1])
        ip_addr = request("GET", "https://ifconfig.me").text
        ec2.authorize_security_group_ingress(
            GroupId=security_group,
            IpPermissions=[
                {
                    'FromPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [
                        {
                            'CidrIp': ip_addr + '/32',
                            'Description': 'SSH access',
                    },
                    ],
                    'ToPort': 22,
                },
            ],
        )
        print(f"The IP {ip_addr} was added to the security grouyp")
    except ClientError as e:
        print(str(e))

def remove_ip_addr(api_keys, security_group, region="ap-south-1"):
    try:
        ec2 = boto3.client('ec2', region, aws_access_key_id = api_keys[0], aws_secret_access_key = api_keys[1])
        ip_addr = request("GET", "https://ifconfig.me").text
        ec2.revoke_security_group_ingress(
            GroupId=security_group,
            IpPermissions=[
                {
                    'FromPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [
                        {
                            'CidrIp': ip_addr + '/32',
                            'Description': 'SSH access',
                    },
                    ],
                    'ToPort': 22,
                },
            ],
        )
    except ClientError as e:
        print(str(e))

if __name__ == "__main__":
    api_keys = list()
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', help = "Region of AWS where the SG exists")
    parser.add_argument('--security_group', help="Security group ID of your security group", required=True)
    parser.add_argument('--delete', help="Removes your IP from security group")
    args = parser.parse_args()
    credentials = expanduser("~/.aws/credentials.csv")
    creds = open(credentials,'r').readlines()
    for secret in creds:
        api_keys.append(secret.split("=")[1].replace("\n",""))
    if args.delete:
        remove_ip_addr(api_keys, security_group = args.security_group, region = args.region)
    else:
        add_ip_addr(api_keys, security_group = args.security_group, region = args.region )
        
    



