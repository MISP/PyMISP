#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from pymisp import ExpandedPyMISP
from pymisp.tools import GenericObjectGenerator
from pymisp.tools import update_objects
from keys import misp_url, misp_key, misp_verifycert
import argparse
import requests
import sys


"""

usage: add_github_user.py [-h] -e EVENT [-f] -u USERNAME

Fetch GitHub user details and add it in object in MISP

optional arguments:
  -h, --help            show this help message and exit
  -e EVENT, --event EVENT
                        Event ID to update
  -f, --force-template-update
  -u USERNAME, --username USERNAME
                        GitHub username to add
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fetch GitHub user details and add it in object in MISP')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update")
    parser.add_argument("-f", "--force-template-update", required=False, action="store_true")
    parser.add_argument("-u", "--username", required=True, help="GitHub username to add")
    args = parser.parse_args()

    r = requests.get("https://api.github.com/users/{}".format(args.username))
    if r.status_code != 200:
       sys.exit("HTTP return is {} and not 200 as expected".format(r.status_code))
    if args.force_template_update:
       print("Updating MISP Object templates...")
       update_objects()
    pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    misp_object = GenericObjectGenerator("github-user")
    github_user = json.loads(r.text)
    rfollowers = requests.get(github_user['followers_url'])
    followers = json.loads(rfollowers.text)
    user_followers = []
    for follower in followers:
        user_followers.append({"follower": follower['login']})
    print(user_followers)
    github_username = [{"bio": github_user['bio'],
                        "link": github_user['html_url'],
                        "user-fullname": github_user['name'],
                        "username": github_user['login']
                        }]
    misp_object.generate_attributes(github_username)
    retcode = pymisp.add_object(args.event, misp_object)
