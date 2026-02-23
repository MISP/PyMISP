#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse

# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == '__main__':

    valid_object_type = {'Attribute', 'Event', 'EventReport', 'GalaxyCluster', 'Galaxy',
                         'Object', 'Note', 'Opinion', 'Relationship', 'Organisation',
                         'SharingGroup'}
    
    parser = argparse.ArgumentParser(description='Add a reference between two objects')
    parser.add_argument("-o", "--object", help="The id, uuid or json of the object referencing.",required=True)
    parser.add_argument("-t", "--target-uuid", help="The uuid of the object referenced.",required=True)
    parser.add_argument("-r", "--relationship-type", help="The type of the relationship",required=True)
    parser.add_argument("--type", help="The type of the referenced object",required=True,choices=valid_object_type)
    args = parser.parse_args()

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    misp_object = misp.get_object(args.object,pythonify=True)

    relationship = misp_object.add_relationship(args.type, args.target_uuid, args.relationship_type)

    print(relationship)
    
    misp.add_relationship(relationship)