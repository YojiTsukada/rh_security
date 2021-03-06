import os
import requests
import json
import base64
import boto3
import datetime

# for time Environment
now = datetime.datetime.now()
dateformat = (now.strftime("%Y%m%d%H%M%S"))
file_name = dateformat + '.json'

# Write on S3
def write_s3(json_file):
    s3 = boto3.resource('s3')
    bucket_name = 'rhsecurity-dump'
    bucket = s3.Bucket(bucket_name)
    bucket.upload_file(json_file, file_name)
    return 


def lambda_handler(event, context):
    
    # Redhat Security API URL
    base_url = 'https://access.redhat.com/labs/securitydataapi/'
    
    # Parameter
    endpoint = 'cvrf.json?'
    date = "after=2018-11-20"
    severity = 'severity=important'
    
    # Build URL
    url = base_url + endpoint + date + "&" + severity
    #data = get_data(endpoint + '?' + params)

    res = requests.get(url)
    data = res.json()
    
    # To check Response 
    if data == []:
        print('No updated.')
        return None

    # Initialize
    sec_dict = {}
    count = 0

    for x in data:
        detail = requests.get(x['resource_url'] ,timeout=10)

        # Only Security Advisory documents.
        if detail.json()['cvrfdoc']['document_type'] == 'Security Advisory':

            # To initialize flag param.
            kernel = ""
            flag = ""

            # exclude kernel packages.
            packages = x['released_packages']
            for package in packages:
                if "kernel" in package:
                    print(x['RHSA'] + ' include kernel package. ' + package)
                    kernel = 1
                    break

            # Only Redhat Linux Products.
            products = (detail.json()['cvrfdoc']['product_tree']['branch'][0]['branch'])
                        
            # Set flag only RedHat Enterprise Linux prouct.
            for product in products:
                
                # To escape that product is strings.
                if isinstance(product, str):
                    break
                
                # Only Red Hat Enterprise Linux Product.
                if product['full_product_name'] == 'Red Hat Enterprise Linux Server (v. 7)':
                    print(product['full_product_name'] + " is muched." + x['RHSA'])
                    flag = 1
                    break
                else:
                    flag = 0
            
            # flag = 1 merged.   
            if flag == 1 and not kernel == 1:

                # Build Security Dictionary
                sec_dict[count] = {}
                sec_dict[count]['RHSA'] = x['RHSA']
                sec_dict[count]['document_title'] = detail.json()['cvrfdoc']['document_title']
                sec_dict[count]['note'] = ','.join(detail.json()['cvrfdoc']['document_notes']['note'])
                sec_dict[count]['released_packages'] = ','.join(x['released_packages'])
                sec_dict[count]['CVEs'] = ','.join(x['CVEs'])
                sec_dict[count]['released_on'] = x['released_on']
                sec_dict[count]['url'] = detail.json()['cvrfdoc']['document_references']['reference'][0]['url']

                count += 1
                
                print(x['RHSA'] + ' is merged.')
            else:
                print(x['RHSA'] + ' is not Redhat Linux product.')


    # Save json file
    with open('/tmp/' + '_security.json', 'w') as f:
        json.dump(sec_dict, f)

    # Write S3
    write_s3('/tmp/' + '_security.json')

    return json.dumps(sec_dict)
