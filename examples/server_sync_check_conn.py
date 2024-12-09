#!/usr/bin/env python

import requests
import json

# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from keys import misp_url, misp_key, misp_verifycert
proxies = {

}

'''
Checks if the connection to a sync server works
returns json object
'''

def check_connection(connection_number):

    misp_headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': misp_key}
    req = requests.get(misp_url + 'servers/testConnection/{}'.format(connection_number), verify=misp_verifycert, headers=misp_headers, proxies=proxies)

    result = json.loads(req.text)
    return(result)


if __name__ == "__main__":

    result = check_connection(1)
    print(result)
