#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Koen Van Impe

List all the sightings

Put this script in crontab to run every day
    25 4    * * *   mispuser   /usr/bin/python3 /home/mispuser/PyMISP/examples/show_sightings.py

'''

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert

import sys
import time
from datetime import datetime
import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
import argparse
import string

def init(url, key, verifycert):
    '''
        Template to get MISP module started
    '''
    return PyMISP(url, key, verifycert, 'json')


def set_drift_timestamp(drift_timestamp, drift_timestamp_path):
    '''
        Save the timestamp in a (local) file
    '''
    try:
        with open(drift_timestamp_path, 'w+') as f:
            f.write(str(drift_timestamp))
        return True
    except IOError:
        sys.exit("Unable to write drift_timestamp %s to %s" % (drift_timestamp, drift_timestamp_path))
        return False


def get_drift_timestamp(drift_timestamp_path):
    '''
        From when do we start with the sightings?
    '''
    try:
        with open(drift_timestamp_path) as f:
            drift = f.read()
            if drift:
                drift = int(float(drift))
            else:
                drift = 0
    except IOError:
        drift = 0

    return drift


def search_sightings(misp, from_timestamp, end_timestamp):
    '''
        Search all the sightings
    '''
    completed_sightings = []

    try:
        found_sightings = misp.search_sightings(date_from=from_timestamp, date_to=end_timestamp)
    except Exception as e:
        sys.exit('Unable to search for sightings')

    if found_sightings is not None:
        for s in found_sightings:
            if 'Sighting' in s:
                sighting = s['Sighting']
                if 'attribute_id' in sighting:
                    attribute_id = sighting['attribute_id']

                    # Query the attribute and event to get the details
                    try:
                        attribute = misp.get_attribute(attribute_id)
                    except Exception as e:
                        print("Unable to fetch attribute")
                        continue

                    if 'Attribute' in attribute and 'uuid' in attribute['Attribute']:
                        event_details = misp.get_event(attribute['Attribute']['event_id'])
                        event_info = event_details['Event']['info']
                        attribute_uuid = attribute['Attribute']['uuid']
                        to_ids = attribute['Attribute']['to_ids']
                        completed_sightings.append({'attribute_uuid': attribute_uuid, 'date_sighting': sighting['date_sighting'], 'source': sighting['source'], 'type': sighting['type'], 'uuid': sighting['uuid'], 'event_id':  attribute['Attribute']['event_id'], 'value':  attribute['Attribute']['value'], 'attribute_id':  attribute['Attribute']['id'], 'event_title': event_info, 'to_ids': to_ids})
                    else:
                        continue

    return completed_sightings


if __name__ == '__main__':
    smtp_from = 'INSERT_FROM'
    smtp_to = 'INSERT_TO'
    smtp_server = 'localhost'
    report_sightings = ''
    ts_format = '%Y-%m-%d %H:%M:%S'
    drift_timestamp_path = '/home/mispuser/PyMISP/examples/show_sightings.drift'

    parser = argparse.ArgumentParser(description="Show all the sightings.")
    parser.add_argument('-m', '--mail', action='store_true', help='Mail the report')
    parser.add_argument('-o', '--mailoptions', action='store', help='mailoptions: \'smtp_from=INSERT_FROM;smtp_to=INSERT_TO;smtp_server=localhost\'')

    args = parser.parse_args()
    misp = init(misp_url, misp_key, misp_verifycert)

    start_timestamp = get_drift_timestamp(drift_timestamp_path=drift_timestamp_path)
    end_timestamp = time.time()
    start_timestamp_s = datetime.fromtimestamp(start_timestamp).strftime(ts_format)
    end_timestamp_s = datetime.fromtimestamp(end_timestamp).strftime(ts_format)

    # Get all attribute sightings
    found_sightings = search_sightings(misp, start_timestamp, end_timestamp)
    if found_sightings:
        for s in found_sightings:
            if int(s['type']) == 0:
                s_type = 'TP'
            else:
                s_type = 'FP'
            date_sighting = datetime.fromtimestamp(int(s['date_sighting'])).strftime(ts_format)
            s_title = s['event_title']
            s_title = s_title.replace('\r','').replace('\n','').replace('\t','')
            source = s['source']
            if not s['source']:
                source = 'N/A'
            report_sightings = report_sightings + '%s for [%s] (%s) in event [%s] (%s) on %s from %s (to_ids flag: %s) \n' % ( s_type, s['value'], s['attribute_id'], s_title, s['event_id'], date_sighting, source, s['to_ids'])

        set_drift_timestamp(end_timestamp, drift_timestamp_path)
    else:
        report_sightings = 'No sightings found'

    # Mail options
    if args.mail:
        if args.mailoptions:
            mailoptions = args.mailoptions.split(';')
            for s in mailoptions:
                if s.split('=')[0] == 'smtp_from':
                    smtp_from = s.split('=')[1]
                if s.split('=')[0] == 'smtp_to':
                    smtp_to = s.split('=')[1]
                if s.split('=')[0] == 'smtp_server':
                    smtp_server = s.split('=')[1]

        report_sightings_body = 'MISP Sightings report for %s between %s and %s\n-------------------------------------------------------------------------------\n\n' % (misp_url, start_timestamp_s, end_timestamp_s)
        report_sightings_body = report_sightings_body + report_sightings
        subject = 'Report of sightings between %s and %s' % (start_timestamp_s, end_timestamp_s)

        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = smtp_to
        msg['Subject'] = subject

        msg.attach(MIMEText(report_sightings_body, 'text'))
        server = smtplib.SMTP(smtp_server)
        server.sendmail(smtp_from, smtp_to, msg.as_string())

    else:
        print(report_sightings)
