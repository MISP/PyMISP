#!/usr/bin/env python
# -*- coding: utf-8 -*-

from json import JSONDecoder
import random
import pygal
from pygal.style import Style
import pandas
from datetime import datetime
from datetime import timedelta
from dateutil.parser import parse

# ############### Errors ################


class DateError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

# ############### Tools ################


def buildDoubleIndex(index1, index2, datatype):
    it = -1
    newindex1 = []
    for index in index2:
        if index == 0:
            it += 1
        newindex1.append(index1[it])
    arrays = [newindex1, index2]
    tuples = list(zip(*arrays))
    return pandas.MultiIndex.from_tuples(tuples, names=['event', datatype])


def buildNewColumn(index2, column):
    it = -1
    newcolumn = []
    for index in index2:
        if index == 0:
            it += 1
        newcolumn.append(column[it])
    return newcolumn


def dateInRange(datetimeTested, begin=None, end=None):
    if begin is None:
        begin = datetime(1970, 1, 1)
    if end is None:
        end = datetime.now()
    return begin <= datetimeTested <= end


def addColumn(dataframe, columnList, columnName):
    dataframe.loc[:, columnName] = pandas.Series(columnList, index=dataframe.index)


def toDatetime(date):
    return parse(date)


def checkDateConsistancy(begindate, enddate, lastdate):
    if begindate is not None and enddate is not None:
        if begindate > enddate:
            raise DateError('begindate ({}) cannot be after enddate ({})'.format(begindate, enddate))

    if enddate is not None:
        if toDatetime(enddate) < lastdate:
            raise DateError('enddate ({}) cannot be before lastdate ({})'.format(enddate, lastdate))

    if begindate is not None:
        if toDatetime(begindate) > datetime.now():
            raise DateError('begindate ({}) cannot be after today ({})'.format(begindate, datetime.now().date()))


def setBegindate(begindate, lastdate):
    return max(begindate, lastdate)


def setEnddate(enddate):
    return min(enddate, datetime.now())


def getLastdate(last):
    return (datetime.now() - timedelta(days=int(last))).replace(hour=0, minute=0, second=0, microsecond=0)

# ############### Formatting  ################


def eventsListBuildFromList(filename):
    with open(filename, 'r') as myfile:
        s = myfile.read().replace('\n', '')
    decoder = JSONDecoder()
    s_len = len(s)
    Events = []
    end = 0
    while end != s_len:
        Event, end = decoder.raw_decode(s, idx=end)
        Events.append(Event)
    data = []
    for e in Events:
        data.append(pandas.DataFrame.from_dict(e, orient='index'))
    Events = pandas.concat(data)
    for it in range(Events['attribute_count'].size):
        if Events['attribute_count'][it] is None:
            Events['attribute_count'][it] = '0'
        else:
            Events['attribute_count'][it] = int(Events['attribute_count'][it])
    Events = Events.set_index('id')
    return Events


def eventsListBuildFromArray(jdata):
    '''
    returns a structure listing all primary events in the sample
    '''
    data = [pandas.DataFrame.from_dict(e, orient='index') for e in jdata['response']]
    events = pandas.concat(data)
    events = events.set_index(['id'])
    return events


def attributesListBuild(events):
    attributes = [pandas.DataFrame(attribute) for attribute in events['Attribute']]
    return pandas.concat(attributes)


def tagsListBuild(Events):
    Tags = []
    for Tag in Events['Tag']:
        if type(Tag) is not list:
            continue
        Tags.append(pandas.DataFrame(Tag))
    Tags = pandas.concat(Tags)
    columnDate = buildNewColumn(Tags.index, Events['date'])
    addColumn(Tags, columnDate, 'date')
    index = buildDoubleIndex(Events.index, Tags.index, 'tag')
    Tags = Tags.set_index(index)
    return Tags


def selectInRange(Events, begin=None, end=None):
    inRange = []
    for i, Event in Events.iterrows():
        if dateInRange(parse(Event['date']), begin, end):
            inRange.append(Event.tolist())
    inRange = pandas.DataFrame(inRange)
    temp = Events.columns.tolist()
    inRange.columns = temp
    return inRange


def isTagIn(dataframe, tag):
    temp = dataframe[dataframe['name'].str.contains(tag)].index.tolist()
    index = []
    for i in range(len(temp)):
        if temp[i][0] not in index:
            index.append(temp[i][0])
    return index

# ############### Basic Stats ################


def getNbitems(dataframe):
        return len(dataframe.index)


def getNbAttributePerEventCategoryType(attributes):
    return attributes.groupby(['event_id', 'category', 'type']).count()['id']


def getNbOccurenceTags(Tags):
        return Tags.groupby('name').count()['id']

# ############### Charts ################


def createTable(colors, categ_types_hash, tablename='attribute_table.html'):
    with open(tablename, 'w') as target:
        target.write('<!DOCTYPE html>\n<html>\n<head>\n<link rel="stylesheet" href="style.css">\n</head>\n<body>')
        for categ_name, types in categ_types_hash.items():
            table = pygal.Treemap(pretty_print=True)
            target.write('\n <h1 style="color:{};">{}</h1>\n'.format(colors[categ_name], categ_name))
            for d in types:
                table.add(d['label'], d['value'])
            target.write(table.render_table(transpose=True))
        target.write('\n</body>\n</html>')


def createTreemap(data, title, treename='attribute_treemap.svg', tablename='attribute_table.html'):
    labels_categ = data.index.labels[0]
    labels_types = data.index.labels[1]
    names_categ = data.index.levels[0]
    names_types = data.index.levels[1]
    categ_types_hash = {}
    for categ_id, type_val, total in zip(labels_categ, labels_types, data):
        if not categ_types_hash.get(names_categ[categ_id]):
            categ_types_hash[names_categ[categ_id]] = []
        dict_to_print = {'label': names_types[type_val], 'value': total}
        categ_types_hash[names_categ[categ_id]].append(dict_to_print)

    colors = {categ: "#%06X" % random.randint(0, 0xFFFFFF) for categ in categ_types_hash.keys()}
    style = Style(background='transparent',
                  plot_background='#FFFFFF',
                  foreground='#111111',
                  foreground_strong='#111111',
                  foreground_subtle='#111111',
                  opacity='.6',
                  opacity_hover='.9',
                  transition='400ms ease-in',
                  colors=tuple(colors.values()))

    treemap = pygal.Treemap(pretty_print=True, legend_at_bottom=True, style=style)
    treemap.title = title
    treemap.print_values = True
    treemap.print_labels = True

    for categ_name, types in categ_types_hash.items():
        treemap.add(categ_name, types)

    createTable(colors, categ_types_hash)
    treemap.render_to_file(treename)
