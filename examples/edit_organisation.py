#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP, MISPOrganisation
from keys import misp_url, misp_key, misp_verifycert
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Edit the email of the organisation designed by the organisation_id.')
    parser.add_argument("-i", "--organisation_id", required=True, help="The name of the json file describing the organisation you want to modify.")
    parser.add_argument("-e", "--email", help="Email linked to the organisation.")
    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    org = MISPOrganisation()
    org.id = args.organisation_id
    org.email = args.email

    print(misp.update_organisation(org, pythonify=True))
