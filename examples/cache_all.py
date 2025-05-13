#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keys import misp_url, misp_key, misp_verifycert
from pymisp import PyMISP


if __name__ == '__main__':
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    misp.cache_all_feeds()
