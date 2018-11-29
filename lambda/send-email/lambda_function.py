import boto3
import json
import os
import bottle
from jinja2 import Environment, FileSystemLoader
import ast

client = boto3.client('ses',region_name='us-east-1')

# Sendmail function
def send_email(source, to, subject, body):
    response = client.send_email(
        Source=source,
        Destination={
            'ToAddresses': [
                to,
            ]
        },
        Message={
            'Subject': {
                'Data': subject,
            },
            'Body': {
                'Text': {
                    'Data': body,
                },
            }
        }
    )
    return response


def replacement_mail(bucket,key):

    # To set S3 clients.
    s3 = boto3.client('s3')

    # read template
    template = './rhsecurity-mailtemp.txt'

    # 
    env = Environment(loader=FileSystemLoader('./', encoding='utf8'))
    tpl = env.get_template(template)

    # get S3 object.
    response = s3.get_object(Bucket=bucket, Key=key)
    content = response['Body'].read().decode('utf-8')
    data = json.loads(content)

    print(type(data))
    
    lists = []

    print(data)
    for num in data:
        lists.append(data[num])

    body = tpl.render({'lists':lists})

    return body

def lambda_handler(event, context):
    
    print(event)
    # To Set Environments.
    from_address = os.environ['FROM_MAIL_ADDR']
    subject = "RedHat / CentOS Secuirty Information."
    dest_address = os.environ['TO_MAIL_ADDR']

    # S3 Bucket (update json.)
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = str(event['Records'][0]['s3']['object']['key'])

    # send mail
    send_email(from_address, dest_address, subject, replacement_mail(bucket,key))
    
    return 