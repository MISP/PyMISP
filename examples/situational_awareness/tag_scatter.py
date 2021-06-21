#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import numpy
import tools
import date_tools
import bokeh_tools

import time

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Show the evolution of trend of tags.')
    parser.add_argument("-d", "--days", type=int, required=True, help='')
    parser.add_argument("-s", "--begindate", required=True, help='format yyyy-mm-dd')
    parser.add_argument("-e", "--enddate", required=True, help='format yyyy-mm-dd')

    args = parser.parse_args()

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    result = misp.search(date_from=args.begindate, date_to=args.enddate, metadata=False)

    # Getting data

    if 'response' in result:
        events = tools.eventsListBuildFromArray(result)
        NbTags = []
        dates = []
        enddate = date_tools.toDatetime(args.enddate)
        begindate = date_tools.toDatetime(args.begindate)

        for i in range(round(date_tools.days_between(enddate, begindate)/args.days)):
            begindate = date_tools.getNDaysBefore(enddate, args.days)
            eventstemp = tools.selectInRange(events, begindate, enddate)
            if eventstemp is not None:
                for event in eventstemp.iterrows():
                    if 'Tag' in event[1]:
                        dates.append(enddate)
                        if isinstance(event[1]['Tag'], list):
                            NbTags.append(len(event[1]['Tag']))
                        else:
                            NbTags.append(0)
            enddate = begindate

    # Prepare plot

    NbTagsPlot = {}
    datesPlot = {}

    for i in range(len(NbTags)):
        if NbTags[i] == -1:
            continue
        count = 1
        for j in range(i+1, len(NbTags)):
            if NbTags[i] == NbTags[j] and dates[i] == dates[j]:
                count = count + 1
                NbTags[j] = -1
        if str(count) in NbTagsPlot:
            NbTagsPlot[str(count)].append(NbTags[i])
            datesPlot[str(count)].append(dates[i])
        else:
            NbTagsPlot[str(count)] = [NbTags[i]]
            datesPlot[str(count)] = [dates[i]]
        NbTags[i] = -1

    # Plot

    bokeh_tools.tagsDistributionScatterPlot(NbTagsPlot, datesPlot)
