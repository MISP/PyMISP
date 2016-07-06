#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json
import tools

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

########## fetch data ##########

def searchall(m, search, url):
    result = m.search_all(search)
    with open('data', 'w') as f:
        f.write(json.dumps(result))

def download_last(m, last):
    result = m.download_last(last)
    with open('data', 'w') as f:
        f.write(json.dumps(result))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Take a sample of events (based on last.py of searchall.py) and create a treemap epresenting the distribution of attributes in this sample.')
    parser.add_argument("-f", "--function", required=True, help="The parameter can be either set to \"last\" or \"searchall\". If the parameter is not valid, \"last\" will be the default setting.")
    parser.add_argument("-a", "--argument", required=True, help="if function is \"last\", time can be defined in days, hours, minutes (for example 5d or 12h or 30m). Otherwise, this argument is the string to search")

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.function == "searchall":
        searchall(misp, args.argument, misp_url)
    else:
        download_last(misp, args.argument)

    Events = tools.eventsListBuildFromArray('data')

    Attributes = tools.attributesListBuild(Events)
    temp = tools.getNbAttributePerEventCategoryType(Attributes)
    temp = temp.groupby(level=['category', 'type']).sum()
    tools.createTreemap(temp, 'Attributes Distribution', 'attribute_treemap.svg', 'attribute_table.html')

