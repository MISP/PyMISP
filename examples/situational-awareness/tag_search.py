#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
from datetime import datetime
import argparse
import json
import tools

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

########## fetch data ##########

def download_last(m, last):
    result = m.download_last(last)
    with open('data', 'w') as f:
        f.write(json.dumps(result))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Take a sample of events (based on last.py) and give the number of occurrence of the given tag in this sample.')
    parser.add_argument("-t", "--tag", required=True, help="tag to search (search for multiple tags is possible by using |. example : \"osint|OSINT\")")
    parser.add_argument("-d", "--days", type=int, help="number of days before today to search. If not define, default value is 7")
    parser.add_argument("-b", "--begindate", help="The research will look for tags attached to events posted at or after the given startdate (format: yyyy-mm-dd): If no date is given, default time is epoch time (1970-1-1)")
    parser.add_argument("-e", "--enddate", help="The research will look for tags attached to events posted at or before the given enddate (format: yyyy-mm-dd): If no date is given, default time is now()")

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.days is None:
        args.days = 7
    download_last(misp, str(args.days) + 'd')

    tools.checkDateConsistancy(args.begindate, args.enddate, tools.getLastdate(args.days))

    if args.begindate is None:
        args.begindate = tools.getLastdate(args.days)
    else:
        args.begindate = tools.setBegindate(tools.toDatetime(args.begindate), tools.getLastdate(args.days))

    if args.enddate is None:
        args.enddate = datetime.now()
    else:
        args.enddate = tools.setEnddate(tools.toDatetime(args.enddate))

    Events = tools.selectInRange(tools.eventsListBuildFromArray('data'), begin=args.begindate, end=args.enddate)
    TotalPeriodEvents = tools.getNbitems(Events)
    Tags = tools.tagsListBuild(Events)
    result = tools.isTagIn(Tags, args.tag)
    TotalPeriodTags = len(result)

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

    print '\n========================================================'
    print text
    print 'During the studied pediod, ' + str(TotalPeriodTags) + ' events out of ' + str(TotalPeriodEvents) + ' contains at least one tag with ' + args.tag + '.'
    if TotalPeriodEvents != 0:
        print 'It represents ' + str(round(100*TotalPeriodTags/TotalPeriodEvents, 3)) + '% of the events in this period.'
