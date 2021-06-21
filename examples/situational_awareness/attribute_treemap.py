#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import tools
import pygal_tools

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Take a sample of events (based on last.py of searchall.py) and create a treemap epresenting the distribution of attributes in this sample.')
    parser.add_argument("-f", "--function", required=True, help='The parameter can be either set to "last" or "searchall". If the parameter is not valid, "last" will be the default setting.')
    parser.add_argument("-a", "--argument", required=True, help='if function is "last", time can be defined in days, hours, minutes (for example 5d or 12h or 30m). Otherwise, this argument is the string to search')

    args = parser.parse_args()

    misp = PyMISP(misp_url, misp_key, misp_verifycert, 'json')

    if args.function == "searchall":
        result = misp.search_all(args.argument)
    else:
        result = misp.download_last(args.argument)

    if 'response' in result:
        events = tools.eventsListBuildFromArray(result)
        attributes = tools.attributesListBuild(events)
        temp = tools.getNbAttributePerEventCategoryType(attributes)
        temp = temp.groupby(level=['category', 'type']).sum()
        pygal_tools.createTreemap(temp, 'Attributes Distribution', 'attribute_treemap.svg', 'attribute_table.html')
    else:
        print ('There is no event answering the research criteria')
