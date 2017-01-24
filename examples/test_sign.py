#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from pymisp import mispevent


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sign & verify a MISP event.')
    parser.add_argument("-i", "--input", required=True, help="Json file")
    parser.add_argument("-u", "--uid", required=True, help="GPG UID")
    args = parser.parse_args()

    me = mispevent.MISPEvent()
    me.load(args.input)

    me.sign(args.uid)
    me.verify(args.uid)
