#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from pymispwarninglists import WarningLists
    has_pymispwarninglists = True
except ImportError:
    has_pymispwarninglists = False


def from_instance(pymisp_instance, slow_search=False):
    """Load the warnindlist from an existing MISP instance
    :pymisp_instance: Already instantialized PyMISP instance."""

    warninglists_index = pymisp_instance.get_warninglists()['Warninglists']
    all_warningslists = []
    for warninglist in warninglists_index:
        wl = pymisp_instance.get_warninglist(warninglist['Warninglist']['id'])['Warninglist']
        wl['list'] = wl.pop('WarninglistEntry')
        all_warningslists.append(wl)

    return WarningLists(slow_search, all_warningslists)


def from_package(slow_search=False):
    return WarningLists(slow_search)
