#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP, MISPEvent
from pymisp.tools import Fail2BanObject
import argparse
from base64 import b64decode

try:
    from keys import misp_url, misp_key, misp_verifycert
except Exception:
    misp_url = 'URL'
    misp_key = 'AUTH_KEY'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add Fail2ban object.')
    parser.add_argument("-b", "--banned_ip", required=True, help="Banned IP address.")
    parser.add_argument("-a", "--attack_type", required=True, help="Type of attack.")
    parser.add_argument("-p", "--processing_timestamp", help="Processing timestamp.")
    parser.add_argument("-f", "--failures", help="Amount of failures that lead to the ban.")
    parser.add_argument("-s", "--sensor", help="Sensor identifier.")
    parser.add_argument("-v", "--victim", help="Victim identifier.")
    parser.add_argument("-l", "--logline", help="Logline (base64 encoded).")
    parser.add_argument("-ap", "--aggregation_period", required=True, help="Max time of the event (1d, 1h, ...).")
    parser.add_argument("-t", "--tag", required=True, help="Tag to search on MISP.")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)

    response = pymisp.search(tags=args.tag, last=args.aggregation_period, published=False)
    me = MISPEvent()
    if 'response' in response and response['response']:
        me.load(response['response'][1])
    else:
        me.add_tag(args.tag)
    parameters = {'banned-ip': args.banned_ip, 'attack-type': args.attack_type, 'processing-timestamp': args.processing_timestamp}
    if args.failures:
        parameters['failures'] = args.failures
    if args.sensor:
        parameters['sensor'] = args.sensor
    if args.victim:
        parameters['victim'] = args.victim
    if args.logline:
        parameters['logline'] = b64decode(args.logline).decode()
    f2b = Fail2BanObject(parameters=parameters, standalone=False)
    me.add_object(f2b)
    pymisp.add_event(me)
