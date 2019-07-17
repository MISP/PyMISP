#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Delete the user with the given id. Keep in mind that disabling users (by setting the disabled flag via an edit) is always prefered to keep user associations to events intact.')
    parser.add_argument("-i", "--user_id", help="The id of the user you want to delete.")
    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    print(misp.delete_user(args.user_id))
