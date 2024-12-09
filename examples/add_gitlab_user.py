#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from pymisp import MISPObject
from pymisp.tools import update_objects
from keys import misp_url, misp_key, misp_verifycert
import argparse
import requests
import sys

"""
usage: add_gitlab_user.py [-h] -e EVENT [-f] -u USERNAME [-l LINK]

Fetch GitLab user details and add it in object in MISP

optional arguments:
  -h, --help            show this help message and exit
  -e EVENT, --event EVENT
                        Event ID to update
  -f, --force-template-update
  -u USERNAME, --username USERNAME
                        GitLab username to add
  -l LINK, --link LINK  Url to access the GitLab instance, Default is
                        www.gitlab.com.
"""

default_url = "http://www.gitlab.com/"

parser = argparse.ArgumentParser(description='Fetch GitLab user details and add it in object in MISP')
parser.add_argument("-e", "--event", required=True, help="Event ID to update")
parser.add_argument("-f", "--force-template-update", required=False, action="store_true")
parser.add_argument("-u", "--username", required=True, help="GitLab username to add")
parser.add_argument("-l", "--link", required=False, help="Url to access the GitLab instance, Default is www.gitlab.com.", default=default_url)
args = parser.parse_args()


r = requests.get("{}api/v4/users?username={}".format(args.link, args.username))
if r.status_code != 200:
    sys.exit("HTTP return is {} and not 200 as expected".format(r.status_code))
if args.force_template_update:
    print("Updating MISP Object templates...")
    update_objects()

gitlab_user = r.json()[0]
pymisp = PyMISP(misp_url, misp_key, misp_verifycert)
print(gitlab_user)

misp_object = MISPObject(name="gitlab-user")
misp_object.add_attribute('username', gitlab_user['username'])
misp_object.add_attribute('id', gitlab_user['id'])
misp_object.add_attribute('name', gitlab_user['name'])
misp_object.add_attribute('state', gitlab_user['state'])
misp_object.add_attribute('avatar_url', gitlab_user['avatar_url'])
misp_object.add_attribute('web_url', gitlab_user['web_url'])
retcode = pymisp.add_object(args.event, misp_object)
