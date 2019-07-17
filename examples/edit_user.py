#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP, MISPUser
from keys import misp_url, misp_key, misp_verifycert
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Edit the email of the user designed by the user_id.')
    parser.add_argument("-i", "--user_id", required=True, help="The name of the json file describing the user you want to modify.")
    parser.add_argument("-e", "--email", help="Email linked to the account.")
    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    user = MISPUser
    user.id = args.user_id
    user.email = args.email

    print(misp.edit_user(user, pythonify=True))
