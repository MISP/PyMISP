#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
from pymisp import PyMISP, MISPObject
from keys import misp_url, misp_key, misp_verifycert
import argparse


"""

Sample usage:

python3 ./add_filetype_object_from_csv.py -e 77bcc9f4-21a8-4252-9353-f4615d6121e3 -f ./attributes.csv


Attribute csv file (2 lines. Each line will be a file MISP Object):

test.pdf;6ff19f8b680df260883d61d7c00db14a8bc57aa0;ea307d60ad0bd1df83ab5119df0bf638;b6c9903c9c38400345ad21faa2df50211d8878c96079c43ae64f35b17c9f74a1
test2.xml;0dcef3d68f43e2badb0bfe3d47fd19633264cd1d;15f453625882f6123e239c9ce2b0fe24;b064514fcc52a769e064c4d61ce0c554fbc81e446af31dddac810879a5ca5b17

"""


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a file type MISP Object starting from attributes in a csv file')
    parser.add_argument("-e", "--event_uuid", required=True, help="Event UUID to update")
    parser.add_argument("-f", "--attr_file", required=True, help="Attribute CSV file path")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

    f = open(args.attr_file, newline='')
    csv_reader = csv.reader(f, delimiter=";")

    for line in csv_reader:
       filename = line[0]
       sha1 = line[1]
       md5 = line[2]
       sha256 = line[3]

       misp_object = MISPObject(name='file', filename=filename)
       obj1 = misp_object.add_attribute("filename", value = filename)
       obj1.add_tag('tlp:green')
       obj2 = misp_object.add_attribute("sha1", value = sha1)
       obj2.add_tag('tlp:amber')
       obj3 = misp_object.add_attribute("md5", value = md5)
       obj3.add_tag('tlp:amber')
       obj4 = misp_object.add_attribute("sha256", value = sha256)
       obj4.add_tag('tlp:amber')
       r = pymisp.add_object(args.event_uuid, misp_object)
       print(line)
    print("\nObjects created :)")
