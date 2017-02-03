#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bokeh.plotting import figure, output_file, show, ColumnDataSource
from bokeh.models import HoverTool
import date_tools


def tagsDistributionScatterPlot(NbTags, dates, plotname='Tags Distribution Plot'):

    output_file(plotname + ".html")

    counts = {}
    glyphs = {}
    desc = {}
    hover = HoverTool()
    plot = figure(plot_width=800, plot_height=800, x_axis_type="datetime", x_axis_label='Date', y_axis_label='Number of tags', tools=[hover])

    for name in NbTags.keys():
        desc[name] = []
        for date in dates[name]:
            desc[name].append(date_tools.datetimeToString(date, "%Y-%m-%d"))
        counts[name] = plot.circle(dates[name], NbTags[name], legend="Number of events with y tags", source=ColumnDataSource(
            data=dict(
                desc=desc[name]
                )
            ))
        glyphs[name] = counts[name].glyph
        glyphs[name].size = int(name) * 2
        hover.tooltips = [("date", "@desc")]
        if int(name) != 0:
            glyphs[name].fill_alpha = 1/int(name)
    show(plot)
