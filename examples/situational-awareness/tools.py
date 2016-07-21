#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from json import JSONDecoder
import math
import random
import pygal
from pygal.style import Style
import pandas as pd
from datetime import datetime
from datetime import timedelta
from dateutil.parser import parse

################ Tools ################

def buildDoubleIndex(index1, index2, datatype):
    it = -1
    newindex1 = []
    for index in index2:
        if index == 0:
            it+=1
        newindex1.append(index1[it])
    arrays =  [newindex1, index2]
    tuples = list(zip(*arrays))
    return pd.MultiIndex.from_tuples(tuples, names=['event', datatype])

def buildNewColumn(index2, column):
    it = -1
    newcolumn = []
    for index in index2:
        if index == 0:
            it+=1
        newcolumn.append(column[it])
    return newcolumn

def dateInRange(datetimeTested, begin=None, end=None):
    if begin == None:
        begin = datetime(1970,1,1)
    if end == None:
        end = datetime.now()
    return begin <= datetimeTested <= end

def addColumn(dataframe, columnList, columnName):
        dataframe.loc[:, columnName] = pd.Series(columnList, index=dataframe.index)

def dateInRange(datetimeTested, begin=None, end=None):
    if begin == None:
        begin = datetime(1970,1,1)
    if end == None:
        end = datetime.now()
    return begin <= datetimeTested <= end

def toDatetime(date):
    temp = date.split('-')
    return datetime(int(temp[0]), int(temp[1]), int(temp[2]))

################ Formatting  ################

def eventsListBuildFromList(filename):
    with open(filename, 'r') as myfile:
        s=myfile.read().replace('\n', '')
    decoder = JSONDecoder()
    s_len = len(s)
    Events = []
    end = 0
    while end != s_len:
        Event, end = decoder.raw_decode(s, idx=end)
        Events.append(Event)
    data = []
    for e in Events:
        data.append(pd.DataFrame.from_dict(e, orient='index'))
    Events = pd.concat(data)
    for it in range(Events['attribute_count'].size):
        if Events['attribute_count'][it] == None:
            Events['attribute_count'][it]='0'
        else:
            Events['attribute_count'][it]=int(Events['attribute_count'][it])
    Events = Events.set_index('id')
    return Events

def eventsListBuildFromArray(filename):
    '''
    returns a structure listing all primary events in the sample
    '''
    jdata = json.load(open(filename))
    jdata = jdata['response']
    Events = []
    for e in jdata:
        Events.append(e)
    data = []
    for e in Events:
        data.append(pd.DataFrame.from_dict(e, orient='index'))
    Events = pd.concat(data)
    for it in range(Events['attribute_count'].size):
        if Events['attribute_count'][it] == None or (isinstance(Events['attribute_count'][it], float) and math.isnan(Events['attribute_count'][it])):
            Events['attribute_count'][it]='0'
        else:
            Events['attribute_count'][it]=int(Events['attribute_count'][it])
    Events = Events.set_index('id')
    return Events

def attributesListBuild(Events):
    Attributes = []
    for Attribute in Events['Attribute']:
        Attributes.append(pd.DataFrame(Attribute))
    return pd.concat(Attributes)

def tagsListBuild(Events):
    Tags = []
    for Tag in Events['Tag']:
        if type(Tag) is not list:
            continue
        Tags.append(pd.DataFrame(Tag))
    Tags = pd.concat(Tags)
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
    inRange = pd.DataFrame(inRange)
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

################ Basic Stats ################

def getNbitems(dataframe):
        return len(dataframe.index)

def getNbAttributePerEventCategoryType(Attributes):
    return Attributes.groupby(['event_id', 'category', 'type']).count()['id']

def getNbOccurenceTags(Tags):
        return Tags.groupby('name').count()['id']

################ Charts ################

def createStyle(indexlevels):
    colorsList = []
    for i in range(len(indexlevels[0])):
        colorsList.append("#%06X" % random.randint(0, 0xFFFFFF))
    style = Style(
                background='transparent',
                plot_background='#FFFFFF',
                foreground='#111111',
                foreground_strong='#111111',
                foreground_subtle='#111111',
                opacity='.6',
                opacity_hover='.9',
                transition='400ms ease-in',
                colors=tuple(colorsList))
    return style, colorsList

def createLabelsTreemap(indexlevels, indexlabels):
    categories_levels = indexlevels[0]
    cat = 0
    types = []
    cattypes = []
    categories_labels = indexlabels[0]
    types_levels = indexlevels[1]
    types_labels = indexlabels[1]

    for it in range(len(indexlabels[0])):
        if categories_labels[it] != cat:
            cattypes.append(types)
            types = []
            cat += 1

        types.append(types_levels[types_labels[it]])
    cattypes.append(types)

    return categories_levels, cattypes


def createTable(data, title, tablename, colorsList):
    if tablename == None:
        target = open('attribute_table.html', 'w')
    else:
        target = open(tablename, 'w')
    target.truncate()
    target.write('<!DOCTYPE html>\n<html>\n<head>\n<link rel="stylesheet" href="style.css">\n</head>\n<body>')
    categories, types = createLabelsTreemap(data.index.levels, data.index.labels)
    it = 0

    for i in range(len(categories)):
        table = pygal.Treemap(pretty_print=True)
        target.write('\n <h1 style="color:'+ colorsList[i]+ ';">' + categories[i] + '</h1>\n')
        for typ in types[i]:
            table.add(typ, data[it])
            it += 1
        target.write(table.render_table(transpose=True))
    target.write('\n</body>\n</html>')
    target.close()


def createTreemap(data, title, treename = 'attribute_treemap.svg', tablename = 'attribute_table.html'):
    style, colorsList = createStyle(data.index.levels)
    treemap = pygal.Treemap(pretty_print=True, legend_at_bottom=True, style = style)
    treemap.title = title
    treemap.print_values = True
    treemap.print_labels = True

    categories, types = createLabelsTreemap(data.index.levels, data.index.labels)
    it = 0

    for i in range(len(categories)):
        types_labels = []
        for typ in types[i]:
            tempdict = {}
            tempdict['label'] = typ
            tempdict['value'] = data[it]
            types_labels.append(tempdict)
            it += 1
        treemap.add(categories[i], types_labels)

    createTable(data, 'Attribute Distribution', tablename, colorsList)
    if treename == None:
        treemap.render_to_file('attribute_treemap.svg')
    else:
        treemap.render_to_file(treename)
