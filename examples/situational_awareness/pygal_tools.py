#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pygal
from pygal.style import Style
import pandas
import random


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
