#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keys import misp_url, misp_key, misp_verifycert
from pymisp import PyMISP


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


if __name__ == '__main__':
    misp = init(misp_url, misp_key)
    misp.cache_all_feeds()