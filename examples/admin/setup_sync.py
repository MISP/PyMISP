#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP
import sys
import json


# NOTE: the user of the API key *need to be a sync user*
remote_url = 'https://misp.remote'
remote_api_key = 'REMOTE KEY FOR SYNC USER'
remote_verify = True

# NOTE: the user of the API key *need to be an admin*
own_url = 'https://misp.own'
own_api_key = 'OWN KEY FOR ADMIN USER'
own_verify = True


remote_misp = PyMISP(url=remote_url, key=remote_api_key, ssl=remote_verify)
sync_config = remote_misp.get_sync_config()

if 'errors' in sync_config:
    print('Sumething went wrong:')
    print(json.dumps(sync_config, indent=2))
    sys.exit(1)
else:
    print('Sucessfully got a sync config:')
    print(json.dumps(sync_config, indent=2))

own_misp = PyMISP(url=own_url, key=own_api_key, ssl=own_verify)
response = own_misp.import_server(sync_config)

if 'errors' in response:
    print('Sumething went wrong:')
    print(json.dumps(response, indent=2))
    sys.exit(1)
else:
    print('Sucessfully added the sync config:')
    print(json.dumps(response, indent=2))
