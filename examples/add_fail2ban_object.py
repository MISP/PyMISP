#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP, MISPEvent
from pymisp.tools import Fail2BanObject
import argparse
from base64 import b64decode
from io import BytesIO
import os
from datetime import date, datetime
from dateutil.parser import parse


try:
    from keys import misp_url, misp_key, misp_verifycert
except Exception:
    misp_url = 'URL'
    misp_key = 'AUTH_KEY'
    misp_verifycert = True


def create_new_event():
    me = MISPEvent()
    me.info = "Fail2Ban blocking"
    me.add_tag(args.tag)
    start = datetime.now()
    me.add_attribute('datetime', start.isoformat(), comment='Start Time')
    return me


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add Fail2ban object.')
    parser.add_argument("-b", "--banned_ip", required=True, help="Banned IP address.")
    parser.add_argument("-a", "--attack_type", required=True, help="Type of attack.")
    parser.add_argument("-t", "--tag", required=True, help="Tag to search on MISP.")
    parser.add_argument("-p", "--processing_timestamp", help="Processing timestamp.")
    parser.add_argument("-f", "--failures", help="Amount of failures that lead to the ban.")
    parser.add_argument("-s", "--sensor", help="Sensor identifier.")
    parser.add_argument("-v", "--victim", help="Victim identifier.")
    parser.add_argument("-l", "--logline", help="Logline (base64 encoded).")
    parser.add_argument("-F", "--logfile", help="Path to a logfile to attach.")
    parser.add_argument("-n", "--force_new", action='store_true', default=False, help="Force new MISP event.")
    parser.add_argument("-d", "--disable_new", action='store_true', default=False, help="Do not create a new Event.")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)
    event_id = -1
    me = None
    if args.force_new:
        me = create_new_event()
    else:
        response = pymisp.search_index(tag=args.tag, timestamp='1h')
        if response['response']:
            if args.disable_new:
                event_id = response['response'][0]['id']
            else:
                last_event_date = parse(response['response'][0]['date']).date()
                nb_attr = response['response'][0]['attribute_count']
                if last_event_date < date.today() or int(nb_attr) > 1000:
                    me = create_new_event()
                else:
                    event_id = response['response'][0]['id']
        else:
            me = create_new_event()

    parameters = {'banned-ip': args.banned_ip, 'attack-type': args.attack_type}
    if args.processing_timestamp:
        parameters['processing-timestamp'] = args.processing_timestamp
    if args.failures:
        parameters['failures'] = args.failures
    if args.sensor:
        parameters['sensor'] = args.sensor
    if args.victim:
        parameters['victim'] = args.victim
    if args.logline:
        parameters['logline'] = b64decode(args.logline).decode()
    if args.logfile:
        with open(args.logfile, 'rb') as f:
            parameters['logfile'] = {'value': os.path.basename(args.logfile),
                                     'data': BytesIO(f.read())}
    f2b = Fail2BanObject(parameters=parameters, standalone=False)
    if me:
        me.add_object(f2b)
        pymisp.add_event(me)
    elif event_id:
        template_id = pymisp.get_object_template_id(f2b.template_uuid)
        a = pymisp.add_object(event_id, template_id, f2b)
