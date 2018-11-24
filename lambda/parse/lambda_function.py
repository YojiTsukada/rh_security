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

    # Initialize
    sec_dict = {}
    count = 0

    for x in data:
        detail = requests.get(x['resource_url'] ,timeout=10)

        # exclude kernel packages.
        packages = x['released_packages']
        for package in packages:
            if "kernel" in package:
                print(x['RHSA'] + ' include kernel package. ' + package)
                break            

        # Only Security Advisory documents.
        if detail.json()['cvrfdoc']['document_type'] == 'Security Advisory':
            
            # Build Security Dictionary
            sec_dict[count] = {}
            sec_dict[count]['RHSA'] = x['RHSA']
            sec_dict[count]['document_title'] = detail.json()['cvrfdoc']['document_title']
            sec_dict[count]['note'] = detail.json()['cvrfdoc']['document_notes']['note']
            sec_dict[count]['CVEs'] = x['CVEs']
            sec_dict[count]['released_on'] = x['released_on']
            sec_dict[count]['url'] = detail.json()['cvrfdoc']['document_references']['reference'][0]['url']

            count += 1
            
        else:
            print(x['RHSA'] + ' is Not Security Severity.')

    return json.dumps(sec_dict)