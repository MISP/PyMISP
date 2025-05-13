#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Koen Van Impe

Disable the to_ids flag of an attribute when there are to many false positives
Put this script in crontab to run every /15 or /60
    */5 *    * * *   mispuser   /usr/bin/python3 /home/mispuser/PyMISP/examples/falsepositive_disabletoids.py

Do inline config in "main"

'''

from pymisp import PyMISP, MISPEvent
from keys import misp_url, misp_key, misp_verifycert
from datetime import datetime
from datetime import date

import datetime as dt
import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
import argparse


def init(url, key, verifycert):
    '''
        Template to get MISP module started
    '''
    return PyMISP(url, key, verifycert, 'json')


if __name__ == '__main__':

    minimal_fp = 0
    threshold_to_ids = .50
    minimal_date_sighting_date = '1970-01-01 00:00:00'

    smtp_from = 'INSERT_FROM'
    smtp_to = 'INSERT_TO'
    smtp_server = 'localhost'
    report_changes = ''
    ts_format = '%Y-%m-%d %H:%M:%S'

    parser = argparse.ArgumentParser(description="Disable the to_ids flag of attributes with a certain number of false positives above a threshold.")
    parser.add_argument('-m', '--mail', action='store_true', help='Mail the report')
    parser.add_argument('-o', '--mailoptions', action='store', help='mailoptions: \'smtp_from=INSERT_FROM;smtp_to=INSERT_TO;smtp_server=localhost\'')
    parser.add_argument('-b', '--minimal-fp', default=minimal_fp, type=int, help='Minimal number of false positive (default: %(default)s )')
    parser.add_argument('-t', '--threshold', default=threshold_to_ids, type=float, help='Threshold false positive/true positive rate (default: %(default)s )')
    parser.add_argument('-d', '--minimal-date-sighting', default=minimal_date_sighting_date, help='Minimal date for sighting (false positive / true positive) (default: %(default)s )')

    args = parser.parse_args()
    misp = init(misp_url, misp_key, misp_verifycert)

    minimal_fp = int(args.minimal_fp)
    threshold_to_ids = args.threshold
    minimal_date_sighting_date = args.minimal_date_sighting
    minimal_date_sighting = int(dt.datetime.strptime(minimal_date_sighting_date, '%Y-%m-%d %H:%M:%S').strftime("%s"))

    # Fetch all the attributes
    result = misp.search('attributes', to_ids=1, include_sightings=1)

    if 'Attribute' in result:
        for attribute in result['Attribute']:
            true_positive = 0
            false_positive = 0
            compute_threshold = 0
            attribute_id = attribute['id']
            attribute_value = attribute['value']
            attribute_uuid = attribute['uuid']
            event_id = attribute['event_id']

            # Only do something if there is a sighting
            if 'Sighting' in attribute:

                for sighting in attribute['Sighting']:
                    if int(sighting['date_sighting']) > minimal_date_sighting:
                        if int(sighting['type']) == 0:
                            true_positive = true_positive + 1
                        elif int(sighting['type']) == 1:
                            false_positive = false_positive + 1

            if false_positive > minimal_fp:
                compute_threshold = false_positive / (true_positive + false_positive)

                if compute_threshold >= threshold_to_ids:
                    # Fetch event title for report text
                    event_details = misp.get_event(event_id)
                    event_info = event_details['Event']['info']

                    misp.update_attribute( { 'uuid': attribute_uuid, 'to_ids': 0})

                    report_changes = report_changes + 'Disable to_ids for [%s] (%s) in event [%s] (%s) - FP: %s TP: %s \n' % (attribute_value, attribute_id, event_info, event_id, false_positive, true_positive)

                    # Changing the attribute to_ids flag sets the event to unpublished
                    misp.publish(event_id)

    # Only send/print the report if it contains content
    if report_changes:
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

            now = datetime.now()
            current_date = now.strftime(ts_format)
            report_changes_body = 'MISP Disable to_ids flags for %s on %s\n-------------------------------------------------------------------------------\n\n' % (misp_url, current_date)
            report_changes_body = report_changes_body + 'Minimal number of false positives before considering threshold: %s\n' % (minimal_fp)
            report_changes_body = report_changes_body + 'Threshold false positives/true positives to disable to_ids flag: %s\n' % (threshold_to_ids)
            report_changes_body = report_changes_body + 'Minimal date for sighting false positives: %s\n\n' % (minimal_date_sighting_date)
            report_changes_body = report_changes_body + report_changes
            report_changes_body = report_changes_body + '\nEvents that have attributes with changed to_ids flag have been republished, without e-mail notification.'
            report_changes_body = report_changes_body + '\n\nMISP Disable to_ids Finished\n'

            subject = 'Report of disable to_ids flag for false positives sightings of %s' % (current_date)
            msg = MIMEMultipart()
            msg['From'] = smtp_from
            msg['To'] = smtp_to
            msg['Subject'] = subject

            msg.attach(MIMEText(report_changes_body, 'text'))
            print(report_changes_body)
            server = smtplib.SMTP(smtp_server)
            server.sendmail(smtp_from, smtp_to, msg.as_string())

        else:
            print(report_changes)
