#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP, MISPUser
from keys import misp_url, misp_key, misp_verifycert
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add a new user by setting the mandory fields.')
    parser.add_argument("-e", "--email", required=True, help="Email linked to the account.")
    parser.add_argument("-o", "--org_id", required=True, help="Organisation linked to the user.")
    parser.add_argument("-r", "--role_id", required=True, help="Role linked to the user.")
    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, 'json')

    user = MISPUser()
    user.email = args.email
    user.org_id = args.org_id
    user.role_id = args.role_id

    print(misp.add_user(user, pythonify=True))
