#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP, MISPOrganisation, MISPSharingGroup
from keys import misp_url, misp_key, misp_verifycert
import argparse
import csv


# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add organizations from a CSV file')
    parser.add_argument("-c", "--csv-import", required=True, help="The CSV file containing the organizations. Format 'orgname,nationality,sector,type,contacts,uuid,local,sharingroup_uuid'")
    args = parser.parse_args()

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    # CSV format
    #   orgname,nationality,sector,type,contacts,uuid,local,sharingroup
    with open(args.csv_import) as csv_file:
        count_orgs = 0
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:

            org = MISPOrganisation()
            org.name = row[0]
            print("Process {}".format(org.name))
            org.nationality = row[1]
            org.sector = row[2]
            org.type = row[3]
            org.contacts = row[4]
            org.uuid = row[5]
            org.local = row[6]

            add_org = misp.add_organisation(org, pythonify=True)

            if 'errors' in add_org:
                print(add_org['errors'])
            else:
                count_orgs = count_orgs + 1
                org_uuid = add_org.uuid

                if org_uuid:
                    sharinggroup = MISPSharingGroup()
                    sharinggroup_uuid = row[7]

                    if sharinggroup_uuid:
                        sharinggroup.uuid = sharinggroup_uuid
                        add_sharing = misp.add_org_to_sharing_group(sharinggroup, org)
                    else:
                        print("Organisation {} not added to sharing group, missing sharing group uuid".format(org.name))

    print("Import finished, {} organisations added".format(count_orgs))
