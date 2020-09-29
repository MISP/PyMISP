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
    pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

    misp_object = MISPObject(name="github-user")
    github_user = r.json()
    rfollowers = requests.get(github_user['followers_url'])
    followers = rfollowers.json()
    rfollowing = requests.get("https://api.github.com/users/{}/following".format(args.username))
    followings = rfollowing.json()
    rkeys = requests.get("https://api.github.com/users/{}/keys".format(args.username))
    keys = rkeys.json()
    misp_object.add_attributes("follower", *[follower['login'] for follower in followers])
    misp_object.add_attributes("following", *[following['login'] for following in followings])
    misp_object.add_attributes("ssh-public-key", *[sshkey['key'] for sshkey in keys])
    misp_object.add_attribute('bio', github_user['bio'])
    misp_object.add_attribute('link', github_user['html_url'])
    misp_object.add_attribute('user-fullname', github_user['name'])
    misp_object.add_attribute('username', github_user['login'])
    misp_object.add_attribute('twitter_username', github_user['twitter_username'])
    misp_object.add_attribute('location', github_user['location'])
    misp_object.add_attribute('company', github_user['company'])
    misp_object.add_attribute('public_gists', github_user['public_gists'])
    misp_object.add_attribute('public_repos', github_user['public_repos'])
    misp_object.add_attribute('blog', github_user['blog'])
    misp_object.add_attribute('node_id', github_user['node_id'])
    retcode = pymisp.add_object(args.event, misp_object)
