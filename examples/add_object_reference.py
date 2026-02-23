#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse

# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add a reference between two objects')
    parser.add_argument("-o", "--object", help="The id, uuid or json of the object referencing.",required=True)
    parser.add_argument("-t", "--target", help="The id, uuid or json of the object referenced.",required=True)
    parser.add_argument("-r", "--relationship-type", help="The type of the relationship",required=True)
    args = parser.parse_args()

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    misp_object = misp.get_object(args.object,pythonify=True)
    target_object = misp.get_object(args.target,pythonify=True)

    object_ref = misp_object.add_reference(target_object.uuid,args.relationship_type)

    print(object_ref)
    
    misp.add_object_reference(object_ref)