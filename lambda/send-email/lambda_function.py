import boto3
import json
import os

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

# Read mail template from S3 bucket.
def read_template():
    s3 = boto3.client('s3')
    bucket_name = 'rhsecurity-template'
    file_name = 'rhsecurity-mailtemp.txt' 
    
    # get S3 object.
    response = s3.get_object(Bucket=bucket_name, Key=file_name)
    body = response['Body'].read()

    # decode to utf-8
    bodystr = body.decode('utf-8')

    return bodystr

def lambda_handler(event, context):
    from_address = event['address']
    subject = "Secuirty Information."
    dest_address = event['address']
    # send mail
    r = send_email(from_address, dest_address, subject, read_template())
    return 