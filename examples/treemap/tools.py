#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from json import JSONDecoder
import random
import pygal
from pygal.style import Style
import pandas as pd

################ Formatting  ################

def eventsListBuildFromList(filename):
    with open('testt', 'r') as myfile:
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
        if Events['attribute_count'][it] == None:
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


################ Basic Stats ################

def getNbAttributePerEventCategoryType(Attributes):
    return Attributes.groupby(['event_id', 'category', 'type']).count()['id']


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
