#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from pymisp.tools import load_warninglists
import argparse
from keys import misp_url, misp_key, misp_verifycert


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Load the warninglists.')
    parser.add_argument("-p", "--package", action='store_true', help="from the PyMISPWarninglists package.")
    parser.add_argument("-r", "--remote", action='store_true', help="from the MISP instance.")

    args = parser.parse_args()

    if args.package:
        print(load_warninglists.from_package())
    elif args.remote:
        pm = PyMISP(misp_url, misp_key, misp_verifycert)
        print(load_warninglists.from_instance(pm))
