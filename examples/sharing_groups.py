#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get a list of the sharing groups from the MISP instance.')

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    sharing_groups = misp.sharing_groups(pythonify=True)
    print(sharing_groups)
