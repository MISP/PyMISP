#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key
import argparse


def init(url, key):
    return PyMISP(url, key)


def loop_attributes(elem):
    if 'Attribute' in elem.keys():
        for attribute in elem['Attribute']:
            if 'warnings' in attribute.keys():
                for warning in attribute['warnings']:
                    print("Value {} has a hit in warninglist with name '{}' and id '{}'".format(warning['value'],
                                                                                                warning[
                                                                                                    'warninglist_name'],
                                                                                                warning[
                                                                                                    'warninglist_id']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Print all warninglist hits for an event.')
    parser.add_argument("eventid", type=str, help="The event id of the event to get info of")
    args = parser.parse_args()
    misp = init(misp_url, misp_key)
    evt = misp.search('events', eventid=args.eventid, includeWarninglistHits=1)['response'][0]['Event']
    if 'warnings' in evt.keys():
        print('warnings in entire event:')
        print(str(evt['warnings']) + '\n')
        print('Warnings at attribute levels:')
        loop_attributes(evt)
        if 'Object' in evt.keys():
            for obj in evt['Object']:
                loop_attributes(obj)
