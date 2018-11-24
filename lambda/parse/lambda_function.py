import os
import requests
import json
import base64


def lambda_handler(event, context):
    
    # Redhat Security API URL
    base_url = 'https://access.redhat.com/labs/securitydataapi/'
    
    # Parameter
    endpoint = 'cvrf.json?'
    date = "after=2018-11-10"
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

    # initalize for lists
    sec_list = []
    tmp_list = []

    secdict = {}

    for x in data:
        detail = requests.get(x['resource_url'] ,timeout=10)

        # exclude kernel packages.
        packages = x['released_packages']
        for package in packages:
            if "kernel" in package:
                print(package + ' is kernel package.')
                break            

        if detail.json()['cvrfdoc']['document_type'] == 'Security Advisory':
            
            # build temporary list.
            tmp_list.append(x['RHSA'])
            tmp_list.append(detail.json()['cvrfdoc']['document_title'])
            tmp_list.append(detail.json()['cvrfdoc']['document_notes']['note'])
            tmp_list.append(detail.json()['cvrfdoc']['document_references']['reference'][0]['url'])
            tmp_list.append(x['released_on']) 
            tmp_list.append(x['CVEs']) 

            # merge.
            sec_list.append(tmp_list)
            tmp_list = []

        else:
            print('Not Security Severity.')

    #return json.dumps(sec_list)
    return sec_list