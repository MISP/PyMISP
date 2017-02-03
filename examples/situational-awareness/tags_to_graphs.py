#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import tools
import date_tools
import bokeh_tools


def formattingDataframe(dataframe, dates, NanValue):
    dataframe.reverse()
    dates.reverse()
    dataframe = tools.concat(dataframe)
    dataframe = tools.renameColumns(dataframe, dates)
    dataframe = tools.replaceNaN(dataframe, 0)
    return dataframe

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Show the evolution of trend of tags.')
    parser.add_argument("-p", "--period", help='Define the studied period. Can be the past year (y), month (m) or week (w). Week is the default value if no valid value is given.')
    parser.add_argument("-a", "--accuracy", help='Define the accuracy of the splits on the studied period. Can be per month (m) -for year only-, week (w) -month only- or day (d). The default value is always the biggest available.')
    parser.add_argument("-o", "--order", type=int, help='Define the accuracy of the curve fitting. Default value is 3')

    args = parser.parse_args()

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    if args.period == "y":
        if args.accuracy == "d":
            split = 360
            size = 1
        else:
            split = 12
            size = 30
        last = '360d'
        title = 'Tags repartition over the last 360 days'
    elif args.period == "m":
        if args.accuracy == "d":
            split = 28
            size = 1
        else:
            split = 4
            size = 7
        last = '28d'
        title = 'Tags repartition over the last 28 days'
    else:
        split = 7
        size = 1
        last = '7d'
        title = 'Tags repartition over the last 7 days'

    result = misp.search(last=last, metadata=True)
    if 'response' in result:
        events = tools.eventsListBuildFromArray(result)
        result = []
        dates = []
        enddate = date_tools.getToday()
        colourDict = {}
        faketag = False

        for i in range(split):
            begindate = date_tools.getNDaysBefore(enddate, size)
            dates.append(str(enddate.date()))
            eventstemp = tools.selectInRange(events, begin=begindate, end=enddate)
            if eventstemp is not None:
                tags = tools.tagsListBuild(eventstemp)
                if tags is not None:
                    tools.createDictTagsColour(colourDict, tags)
                    result.append(tools.getNbOccurenceTags(tags))
                else:
                    result.append(tools.createFakeEmptyTagsSeries())
                    faketag = True
            else:
                result.append(tools.createFakeEmptyTagsSeries())
                faketag = True
            enddate = begindate

        result = formattingDataframe(result, dates, 0)
        if faketag:
            result = tools.removeFaketagRow(result)

        taxonomies, emptyOther = tools.getTaxonomies(tools.getCopyDataframe(result))

        tools.tagsToLineChart(tools.getCopyDataframe(result), title, dates, colourDict)
        tools.tagstrendToLineChart(tools.getCopyDataframe(result), title, dates, split, colourDict)
        tools.tagsToTaxoLineChart(tools.getCopyDataframe(result), title, dates, colourDict, taxonomies, emptyOther)
        tools.tagstrendToTaxoLineChart(tools.getCopyDataframe(result), title, dates, split, colourDict, taxonomies, emptyOther)
        if args.order is None:
            args.order = 3
        tools.tagsToPolyChart(tools.getCopyDataframe(result), split, colourDict, taxonomies, emptyOther, args.order)
        tools.createVisualisation(taxonomies)

    else:
        print('There is no event during the studied period')
