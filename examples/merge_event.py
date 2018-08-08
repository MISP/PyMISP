#!/usr/bin/env python3

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


def init(misp_url, misp_key, misp_verifycert):
	return PyMISP(misp_url, misp_key, misp_verifycert, debug=False)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Merge Two event from a MISP instance.')
	parser.add_argument("-p", "--previous", required=True, help="Event ID to merge and delete")
	parser.add_argument("-f", "--final", required=True, help="Final event")
	parser.add_argument("-d", "--delete", required=False, action='store_true', help="Final event")
	
	args = parser.parse_args()
	
	misp = init(misp_url, misp_key, misp_verifycert)
	misp.merge_event(args.previous, args.final, args.delete)
