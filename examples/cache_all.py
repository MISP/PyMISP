#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keys import misp_url, misp_key, misp_verifycert
from pymisp import ExpandedPyMISP


if __name__ == '__main__':
    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    misp.cache_all_feeds()
