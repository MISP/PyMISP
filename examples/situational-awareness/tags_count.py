#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
from datetime import datetime
import argparse
import tools
import date_tools


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

# ######### fetch data ##########


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Take a sample of events (based on last.py) and give the repartition of tags in this sample.')
    parser.add_argument("-d", "--days", type=int, help="number of days before today to search. If not define, default value is 7")
    parser.add_argument("-b", "--begindate", default='1970-01-01', help="The research will look for tags attached to events posted at or after the given startdate (format: yyyy-mm-dd): If no date is given, default time is epoch time (1970-1-1)")
    parser.add_argument("-e", "--enddate", help="The research will look for tags attached to events posted at or before the given enddate (format: yyyy-mm-dd): If no date is given, default time is now()")

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.days is None:
        args.days = 7
    result = misp.search(last='{}d'.format(args.days), metadata=True)

    date_tools.checkDateConsistancy(args.begindate, args.enddate, date_tools.getLastdate(args.days))

    if args.begindate is None:
        args.begindate = date_tools.getLastdate(args.days)
    else:
        args.begindate = date_tools.setBegindate(date_tools.toDatetime(args.begindate), date_tools.getLastdate(args.days))

    if args.enddate is None:
        args.enddate = datetime.now()
    else:
        args.enddate = date_tools.setEnddate(date_tools.toDatetime(args.enddate))

    if 'response' in result:
        events = tools.selectInRange(tools.eventsListBuildFromArray(result), begin=args.begindate, end=args.enddate)
        tags = tools.tagsListBuild(events)
        result = tools.getNbOccurenceTags(tags)
    else:
        result = 'There is no event during the studied period'

    text = 'Studied pediod: from '
    if args.begindate is None:
        text = text + '1970-01-01'
    else:
        text = text + str(args.begindate.date())
        text = text + ' to '
    if args.enddate is None:
        text = text + str(datetime.now().date())
    else:
        text = text + str(args.enddate.date())

    print('\n========================================================')
    print(text)
    print(result)
