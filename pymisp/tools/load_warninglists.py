#!/usr/bin/env python

from __future__ import annotations

from ..api import PyMISP

try:
    from pymispwarninglists import WarningLists, WarningList  # type: ignore
    has_pymispwarninglists = True
except ImportError:
    has_pymispwarninglists = False


def from_instance(pymisp_instance: PyMISP, slow_search: bool=False) -> WarningLists:
    """Load the warnindlist from an existing MISP instance
    :pymisp_instance: Already instantialized PyMISP instance."""

    warninglists_index = pymisp_instance.warninglists(pythonify=True)
    all_warningslists = []
    for warninglist in warninglists_index:
        if isinstance(warninglist, WarningList):
            wl = pymisp_instance.get_warninglist(warninglist['Warninglist']['id'])['Warninglist']
            wl['list'] = wl.pop('WarninglistEntry')
            all_warningslists.append(wl)

    return WarningLists(slow_search, all_warningslists)


def from_package(slow_search: bool=False) -> WarningLists:
    return WarningLists(slow_search)
