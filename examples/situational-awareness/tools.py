#!/usr/bin/env python
# -*- coding: utf-8 -*-

from json import JSONDecoder
import pygal
from pygal.style import Style
import pandas
import numpy
from scipy import stats
from pytaxonomies import Taxonomies
import re
import matplotlib.pyplot as plt
from matplotlib import pylab
import os
import date_tools
from dateutil.parser import parse

# ############### Tools ################


def selectInRange(Events, begin=None, end=None):
    inRange = []
    for i, Event in Events.iterrows():
        if date_tools.dateInRange(parse(Event['date']), begin, end):
            inRange.append(Event.tolist())
    inRange = pandas.DataFrame(inRange)
    temp = Events.columns.tolist()
    if inRange.empty:
        return None
    inRange.columns = temp
    return inRange


def getTaxonomies(dataframe):
    taxonomies = Taxonomies()
    taxonomies = list(taxonomies.keys())
    notInTaxo = []
    count = 0
    for taxonomy in taxonomies:
        empty = True
        for it in dataframe.iterrows():
            if it[0].startswith(taxonomy):
                empty = False
                dataframe = dataframe.drop([it[0]])
                count = count + 1
        if empty is True:
            notInTaxo.append(taxonomy)
    if dataframe.empty:
        emptyOther = True
    else:
        emptyOther = False
    for taxonomy in notInTaxo:
        taxonomies.remove(taxonomy)
    return taxonomies, emptyOther


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


def addColumn(dataframe, columnList, columnName):
    dataframe.loc[:, columnName] = pandas.Series(columnList, index=dataframe.index)


def concat(data):
    return pandas.concat(data, axis=1)


def createFakeEmptyTagsSeries():
    return pandas.Series({'Faketag': 0})


def removeFaketagRow(dataframe):
    return dataframe.drop(['Faketag'])


def getCopyDataframe(dataframe):
    return dataframe.copy()


def createDictTagsColour(colourDict, tags):
    temp = tags.groupby(['name', 'colour']).count()['id']
    levels_name = temp.index.levels[0]
    levels_colour = temp.index.levels[1]
    labels_name = temp.index.labels[0]
    labels_colour = temp.index.labels[1]

    for i in range(len(labels_name)):
        colourDict[levels_name[labels_name[i]]] = levels_colour[labels_colour[i]]


def createTagsPlotStyle(dataframe, colourDict, taxonomy=None):
    colours = []
    if taxonomy is not None:
        for it in dataframe.iterrows():
            if it[0].startswith(taxonomy):
                colours.append(colourDict[it[0]])
    else:
        for it in dataframe.iterrows():
            colours.append(colourDict[it[0]])

    style = Style(background='transparent',
                  plot_background='#eeeeee',
                  foreground='#111111',
                  foreground_strong='#111111',
                  foreground_subtle='#111111',
                  opacity='.6',
                  opacity_hover='.9',
                  transition='400ms ease-in',
                  colors=tuple(colours))
    return style

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
    if 'Tag' in Events.columns:
        for Tag in Events['Tag']:
            if type(Tag) is not list:
                continue
            Tags.append(pandas.DataFrame(Tag))
    if Tags:
        Tags = pandas.concat(Tags)
        columnDate = buildNewColumn(Tags.index, Events['date'])
        addColumn(Tags, columnDate, 'date')
        index = buildDoubleIndex(Events.index, Tags.index, 'tag')
        Tags = Tags.set_index(index)
    else:
        Tags = None
    return Tags


def isTagIn(dataframe, tag):
    temp = dataframe[dataframe['name'].str.contains(tag)].index.tolist()
    index = []
    for i in range(len(temp)):
        if temp[i][0] not in index:
            index.append(temp[i][0])
    return index


def renameColumns(dataframe, namelist):
    dataframe.columns = namelist
    return dataframe


def replaceNaN(dataframe, value):
    return dataframe.fillna(value)

# ############### Basic Stats ################


def getNbitems(dataframe):
        return len(dataframe.index)


def getNbAttributePerEventCategoryType(attributes):
    return attributes.groupby(['event_id', 'category', 'type']).count()['id']


def getNbOccurenceTags(Tags):
        return Tags.groupby('name').count()['id']


# ############### Charts ################


def tagsToLineChart(dataframe, title, dates, colourDict):
    style = createTagsPlotStyle(dataframe, colourDict)
    line_chart = pygal.Line(x_label_rotation=20, style=style, show_legend=False)
    line_chart.title = title
    line_chart.x_labels = dates
    for it in dataframe.iterrows():
        line_chart.add(it[0], it[1].tolist())
    line_chart.render_to_file('tags_repartition_plot.svg')


def tagstrendToLineChart(dataframe, title, dates, split, colourDict):
    style = createTagsPlotStyle(dataframe, colourDict)
    line_chart = pygal.Line(x_label_rotation=20, style=style, show_legend=False)
    line_chart.title = title
    line_chart.x_labels = dates
    xi = numpy.arange(split)
    for it in dataframe.iterrows():
        slope, intercept, r_value, p_value, std_err = stats.linregress(xi, it[1])
        line = slope * xi + intercept
        line_chart.add(it[0], line, show_dots=False)
    line_chart.render_to_file('tags_repartition_trend_plot.svg')


def tagsToTaxoLineChart(dataframe, title, dates, colourDict, taxonomies, emptyOther):
    style = createTagsPlotStyle(dataframe, colourDict)
    line_chart = pygal.Line(x_label_rotation=20, style=style)
    line_chart.title = title
    line_chart.x_labels = dates
    for taxonomy in taxonomies:
        taxoStyle = createTagsPlotStyle(dataframe, colourDict, taxonomy)
        taxo_line_chart = pygal.Line(x_label_rotation=20, style=taxoStyle)
        taxo_line_chart.title = title + ': ' + taxonomy
        taxo_line_chart.x_labels = dates
        for it in dataframe.iterrows():
            if it[0].startswith(taxonomy):
                taxo_line_chart.add(re.sub(taxonomy + ':', '', it[0]), it[1].tolist())
                dataframe = dataframe.drop([it[0]])
        taxo_line_chart.render_to_file('plot/' + taxonomy + '.svg')

    if not emptyOther:
        taxoStyle = createTagsPlotStyle(dataframe, colourDict)
        taxo_line_chart = pygal.Line(x_label_rotation=20, style=taxoStyle)
        taxo_line_chart.title = title + ': other'
        taxo_line_chart.x_labels = dates
        for it in dataframe.iterrows():
            taxo_line_chart.add(it[0], it[1].tolist())
        taxo_line_chart.render_to_file('plot/other.svg')


def tagstrendToTaxoLineChart(dataframe, title, dates, split, colourDict, taxonomies, emptyOther):
    style = createTagsPlotStyle(dataframe, colourDict)
    line_chart = pygal.Line(x_label_rotation=20, style=style)
    line_chart.title = title
    line_chart.x_labels = dates
    xi = numpy.arange(split)
    for taxonomy in taxonomies:
        taxoStyle = createTagsPlotStyle(dataframe, colourDict, taxonomy)
        taxo_line_chart = pygal.Line(x_label_rotation=20, style=taxoStyle)
        taxo_line_chart.title = title + ': ' + taxonomy
        taxo_line_chart.x_labels = dates
        for it in dataframe.iterrows():
            if it[0].startswith(taxonomy):
                slope, intercept, r_value, p_value, std_err = stats.linregress(xi, it[1])
                line = slope * xi + intercept
                taxo_line_chart.add(re.sub(taxonomy + ':', '', it[0]), line, show_dots=False)
                dataframe = dataframe.drop([it[0]])
        taxo_line_chart.render_to_file('plot/' + taxonomy + '_trend.svg')

    if not emptyOther:
        taxoStyle = createTagsPlotStyle(dataframe, colourDict)
        taxo_line_chart = pygal.Line(x_label_rotation=20, style=taxoStyle)
        taxo_line_chart.title = title + ': other'
        taxo_line_chart.x_labels = dates
        for it in dataframe.iterrows():
            slope, intercept, r_value, p_value, std_err = stats.linregress(xi, it[1])
            line = slope * xi + intercept
            taxo_line_chart.add(it[0], line, show_dots=False)
        taxo_line_chart.render_to_file('plot/other_trend.svg')


def tagsToPolyChart(dataframe, split, colourDict, taxonomies, emptyOther, order):
    for taxonomy in taxonomies:
        for it in dataframe.iterrows():
            if it[0].startswith(taxonomy):
                points = []
                for i in range(split):
                    points.append((i, it[1][i]))
                color = colourDict[it[0]]
                label = re.sub(taxonomy + ':', '', it[0])
                points = numpy.array(points)
                dataframe = dataframe.drop([it[0]])

                # get x and y vectors
                x = points[:, 0]
                y = points[:, 1]

                # calculate polynomial
                z = numpy.polyfit(x, y, order)
                f = numpy.poly1d(z)

                # calculate new x's and y's
                x_new = numpy.linspace(x[0], x[-1], 50)
                y_new = f(x_new)

                plt.plot(x, y, '.', color=color)
                plt.plot(x_new, y_new, color=color, label=label + 'trend')

        pylab.title('Polynomial Fit with Matplotlib: ' + taxonomy)
        pylab.legend(loc='center left', bbox_to_anchor=(1, 0.5))
        ax = plt.gca()
        # ax.set_facecolor((0.898, 0.898, 0.898))
        box = ax.get_position()
        ax.set_position([box.x0 - 0.01, box.y0, box.width * 0.78, box.height])
        fig = plt.gcf()
        fig.set_size_inches(20, 15)
        fig.savefig('plotlib/' + taxonomy + '.png')
        fig.clf()

    if not emptyOther:
        for it in dataframe.iterrows():
            points = []
            for i in range(split):
                points.append((i, it[1][i]))

            color = colourDict[it[0]]
            label = it[0]
            points = numpy.array(points)

            # get x and y vectors
            x = points[:, 0]
            y = points[:, 1]

            # calculate polynomial
            z = numpy.polyfit(x, y, order)
            f = numpy.poly1d(z)

            # calculate new x's and y's
            x_new = numpy.linspace(x[0], x[-1], 50)
            y_new = f(x_new)

            plt.plot(x, y, '.', color=color, label=label)
            plt.plot(x_new, y_new, color=color, label=label + 'trend')

        pylab.title('Polynomial Fit with Matplotlib: other')
        pylab.legend(loc='center left', bbox_to_anchor=(1, 0.5))
        ax = plt.gca()
        #cax.set_facecolor((0.898, 0.898, 0.898))
        box = ax.get_position()
        ax.set_position([box.x0 - 0.01, box.y0, box.width * 0.78, box.height])
        fig = plt.gcf()
        fig.set_size_inches(20, 15)
        fig.savefig('plotlib/other.png')


def createVisualisation(taxonomies):
    chain = '<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<link rel="stylesheet" href="style2.css">\n\t</head>\n\t<body>'
    chain = chain + '<table>'
    for taxonomy in taxonomies:
        chain = chain + '<tr><td><object type="image/svg+xml" data="plot\\' + taxonomy + '.svg"></object></td><td><img src="plotlib\\' + taxonomy + '.png" alt="graph" /></td><td><object type="image/svg+xml" data="plot\\' + taxonomy + '_trend.svg"></object></td></tr>\n'

    chain = chain + '<tr><td><object type="image/svg+xml" data="plot\other.svg"></object></td><td><img src="plotlib\other.png" alt="graph" /></td><td><object type="image/svg+xml" data="plot\other_trend.svg"></object></td></tr>\n'
    chain = chain + '</table>'
    chain = chain + '\n\t</body>\n</html>'

    with open('test_tags_trend.html', 'w') as target:
        target.write(chain)
