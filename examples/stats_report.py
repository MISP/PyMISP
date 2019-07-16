#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Koen Van Impe

Generate a report of your MISP statistics
Put this script in crontab to run every /15 or /60
    */5 *    * * *   mispuser   /usr/bin/python3 /home/mispuser/PyMISP/examples/stats_report.py -t 30d -m -v

Do inline config in "main"

'''

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
from datetime import datetime
import time
import sys
import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText

# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def init(url, key, verifycert):
    '''
        Template to get MISP module started
    '''
    return PyMISP(url, key, verifycert, 'json')



def get_data(misp, timeframe):
    '''
        Get the event date to build our report
    '''
    number_of_misp_events = 0
    number_of_attributes = 0
    number_of_attributes_to_ids = 0
    attr_type = {}
    attr_category = {}
    tags_type = {}
    tags_tlp = {'tlp:white': 0, 'tlp:green': 0, 'tlp:amber': 0, 'tlp:red': 0}
    tags_misp_galaxy_mitre = {}
    tags_misp_galaxy = {}
    tags_misp_galaxy_threat_actor = {}
    galaxies = {}
    galaxies_cluster = {}
    threat_levels_counts = [0, 0, 0, 0]
    analysis_completion_counts = [0, 0, 0]
    report = {}

    try:
        stats_event = misp.search(last=timeframe)
        stats_event_response = stats_event['response']

        # Number of new or updated events since timestamp
        report['number_of_misp_events'] = len(stats_event_response)
        report['misp_events'] = []

        for event in stats_event_response:
            event_data = event['Event']

            timestamp = datetime.utcfromtimestamp(int(event_data['timestamp'])).strftime(ts_format)
            publish_timestamp = datetime.utcfromtimestamp(int(event_data['publish_timestamp'])).strftime(ts_format)

            threat_level_id = int(event_data['threat_level_id']) - 1
            threat_levels_counts[threat_level_id] = threat_levels_counts[threat_level_id] + 1
            threat_level_id = threat_levels[threat_level_id]

            analysis_id = int(event_data['analysis'])
            analysis_completion_counts[analysis_id] = analysis_completion_counts[analysis_id] + 1
            analysis = analysis_completion[analysis_id]

            report['misp_events'].append({'id': event_data['id'], 'title': event_data['info'].replace('\n', '').encode('utf-8'), 'date': event_data['date'], 'timestamp': timestamp, 'publish_timestamp': publish_timestamp, 'threat_level': threat_level_id, 'analysis_completion': analysis})

            # Walk through the attributes
            if 'Attribute' in event_data:
                event_attr = event_data['Attribute']
                for attr in event_attr:
                    number_of_attributes = number_of_attributes + 1

                    type = attr['type']
                    category = attr['category']
                    to_ids = attr['to_ids']

                    if to_ids:
                        number_of_attributes_to_ids = number_of_attributes_to_ids + 1

                    if type in attr_type:
                        attr_type[type] = attr_type[type] + 1
                    else:
                        attr_type[type] = 1

                    if category in attr_category:
                        attr_category[category] = attr_category[category] + 1
                    else:
                        attr_category[category] = 1
            report['number_of_attributes'] = number_of_attributes
            report['number_of_attributes_to_ids'] = number_of_attributes_to_ids
            report['attr_type'] = attr_type
            report['attr_category'] = attr_category

            # Process tags
            if 'Tag' in event_data:
                tags_attr = event_data['Tag']
                for tag in tags_attr:
                    tag_title = tag['name']

                    if tag_title.lower().replace(' ', '') in tags_tlp:
                        tags_tlp[tag_title.lower().replace(' ', '')] = tags_tlp[tag_title.lower().replace(' ', '')] + 1

                    if 'misp-galaxy:mitre-' in tag_title:
                        if tag_title in tags_misp_galaxy_mitre:
                            tags_misp_galaxy_mitre[tag_title] = tags_misp_galaxy_mitre[tag_title] + 1
                        else:
                            tags_misp_galaxy_mitre[tag_title] = 1

                    if 'misp-galaxy:threat-actor=' in tag_title:
                        if tag_title in tags_misp_galaxy_threat_actor:
                            tags_misp_galaxy_threat_actor[tag_title] = tags_misp_galaxy_threat_actor[tag_title] + 1
                        else:
                            tags_misp_galaxy_threat_actor[tag_title] = 1
                    elif 'misp-galaxy:' in tag_title:
                        if tag_title in tags_misp_galaxy:
                            tags_misp_galaxy[tag_title] = tags_misp_galaxy[tag_title] + 1
                        else:
                            tags_misp_galaxy[tag_title] = 1

                    if tag_title in tags_type:
                        tags_type[tag_title] = tags_type[tag_title] + 1
                    else:
                        tags_type[tag_title] = 1
            report['tags_type'] = tags_type
            report['tags_tlp'] = tags_tlp
            report['tags_misp_galaxy_mitre'] = tags_misp_galaxy_mitre
            report['tags_misp_galaxy'] = tags_misp_galaxy
            report['tags_misp_galaxy_threat_actor'] = tags_misp_galaxy_threat_actor

            # Process the galaxies
            if 'Galaxy' in event_data:
                galaxy_attr = event_data['Galaxy']
                for galaxy in galaxy_attr:
                    galaxy_title = galaxy['type']

                    if galaxy_title in galaxies:
                        galaxies[galaxy_title] = galaxies[galaxy_title] + 1
                    else:
                        galaxies[galaxy_title] = 1

                    for cluster in galaxy['GalaxyCluster']:
                        cluster_value = cluster['type']
                        if cluster_value in galaxies_cluster:
                            galaxies_cluster[cluster_value] = galaxies_cluster[cluster_value] + 1
                        else:
                            galaxies_cluster[cluster_value] = 1
            report['galaxies'] = galaxies
            report['galaxies_cluster'] = galaxies_cluster

        # General MISP statistics
        user_statistics = misp.get_users_statistics()
        if user_statistics:
            report['user_statistics'] = user_statistics

        # Return the report data
        return report
    except Exception as e:
        sys.exit('Unable to get statistics from MISP')



def build_report(report, timeframe, misp_url):
    '''
        Build the body of the report and optional attachments
    '''
    attachments = {}

    now = datetime.now()
    current_date = now.strftime(ts_format)
    report_body = 'MISP Report %s for last %s on %s\n-------------------------------------------------------------------------------' % (current_date, timeframe, misp_url)
    report_body = report_body + '\nNew or updated events: %s' % report['number_of_misp_events']
    report_body = report_body + '\nNew or updated attributes: %s' % report['number_of_attributes']
    report_body = report_body + '\nNew or updated attributes with IDS flag: %s' % report['number_of_attributes_to_ids']
    report_body = report_body + '\n'
    report_body = report_body + '\nTotal events: %s' % report['user_statistics']['stats']['event_count']
    report_body = report_body + '\nTotal attributes: %s' % report['user_statistics']['stats']['attribute_count']
    report_body = report_body + '\nTotal users: %s' % report['user_statistics']['stats']['user_count']
    report_body = report_body + '\nTotal orgs: %s' % report['user_statistics']['stats']['org_count']
    report_body = report_body + '\nTotal correlation: %s' % report['user_statistics']['stats']['correlation_count']
    report_body = report_body + '\nTotal proposals: %s' % report['user_statistics']['stats']['proposal_count']

    report_body = report_body + '\n\n'

    if args.mispevent:
        report_body = report_body + '\nNew or updated events\n-------------------------------------------------------------------------------'
        attachments['misp_events'] = 'ID;Title;Date;Updated;Published;ThreatLevel;AnalysisStatus'
        for el in report['misp_events']:
            report_body = report_body + '\n #%s %s (%s) \t%s \n\t\t\t\t(Date: %s, Updated: %s, Published: %s)' % (el['id'], el['threat_level'], el['analysis_completion'], el['title'], el['date'], el['timestamp'], el['publish_timestamp'])
            attachments['misp_events'] = attachments['misp_events'] + '\n%s;%s;%s;%s;%s;%s;%s' % (el['id'], el['title'], el['date'], el['timestamp'], el['publish_timestamp'], el['threat_level'], el['analysis_completion'])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nNew or updated attributes - Category \n-------------------------------------------------------------------------------'
    attr_category_s = sorted(report['attr_category'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['attr_category'] = 'AttributeCategory;Qt'
    for el in attr_category_s:
        report_body = report_body + '\n%s \t %s' % (el[0], el[1])
        attachments['attr_category'] = attachments['attr_category'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nNew or updated attributes - Type \n-------------------------------------------------------------------------------'
    attr_type_s = sorted(report['attr_type'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['attr_type'] = 'AttributeType;Qt'
    for el in attr_type_s:
        report_body = report_body + '\n%s \t %s' % (el[0], el[1])
        attachments['attr_type'] = attachments['attr_type'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nTLP Codes \n-------------------------------------------------------------------------------'
    attachments['tags_tlp'] = 'TLP;Qt'
    for el in report['tags_tlp']:
        report_body = report_body + "\n%s \t %s" % (el, report['tags_tlp'][el])
        attachments['tags_tlp'] = attachments['tags_tlp'] + '\n%s;%s' % (el, report['tags_tlp'][el])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nTag MISP Galaxy\n-------------------------------------------------------------------------------'
    tags_misp_galaxy_s = sorted(report['tags_misp_galaxy'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['tags_misp_galaxy'] = 'MISPGalaxy;Qt'
    for el in tags_misp_galaxy_s:
        report_body = report_body + "\n%s \t %s" % (el[0], el[1])
        attachments['tags_misp_galaxy'] = attachments['tags_misp_galaxy'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nTag MISP Galaxy Mitre \n-------------------------------------------------------------------------------'
    tags_misp_galaxy_mitre_s = sorted(report['tags_misp_galaxy_mitre'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['tags_misp_galaxy_mitre'] = 'MISPGalaxyMitre;Qt'
    for el in tags_misp_galaxy_mitre_s:
        report_body = report_body + "\n%s \t %s" % (el[0], el[1])
        attachments['tags_misp_galaxy_mitre'] = attachments['tags_misp_galaxy_mitre'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nTag MISP Galaxy Threat Actor \n-------------------------------------------------------------------------------'
    tags_misp_galaxy_threat_actor_s = sorted(report['tags_misp_galaxy_threat_actor'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['tags_misp_galaxy_threat_actor'] = 'MISPGalaxyThreatActor;Qt'
    for el in tags_misp_galaxy_threat_actor_s:
        report_body = report_body + "\n%s \t %s" % (el[0], el[1])
        attachments['tags_misp_galaxy_threat_actor'] = attachments['tags_misp_galaxy_threat_actor'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nTags \n-------------------------------------------------------------------------------'
    tags_type_s = sorted(report['tags_type'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['tags_type'] = 'Tag;Qt'
    for el in tags_type_s:
        report_body = report_body + "\n%s \t %s" % (el[0], el[1])
        attachments['tags_type'] = attachments['tags_type'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nGalaxies \n-------------------------------------------------------------------------------'
    galaxies_s = sorted(report['galaxies'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['galaxies'] = 'Galaxies;Qt'
    for el in galaxies_s:
        report_body = report_body + "\n%s \t %s" % (el[0], el[1])
        attachments['galaxies'] = attachments['galaxies'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + '\n\n'

    report_body = report_body + '\nGalaxies Cluster \n-------------------------------------------------------------------------------'
    galaxies_cluster_s = sorted(report['galaxies_cluster'].items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    attachments['galaxies_cluster'] = 'Galaxies;Qt'
    for el in galaxies_cluster_s:
        report_body = report_body + "\n%s \t %s" % (el[0], el[1])
        attachments['galaxies_cluster'] = attachments['galaxies_cluster'] + '\n%s;%s' % (el[0], el[1])

    report_body = report_body + "\n\nMISP Reporter Finished\n"

    return report_body, attachments



def msg_attach(content, filename):
    '''
        Return an message attachment object
    '''
    part = MIMEBase('application', "octet-stream")
    part.set_payload(content)
    part.add_header('Content-Disposition', 'attachment; filename="%s"' % filename)
    return part



def print_report(report_body, attachments, smtp_from, smtp_to, smtp_server, misp_url):
    '''
        Print (or send) the report
    '''
    if args.mail:
        now = datetime.now()
        current_date = now.strftime(ts_format)

        subject = "MISP Report %s for last %s on %s" % (current_date, timeframe, misp_url)

        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = smtp_to
        msg['Subject'] = subject

        msg.attach(MIMEText(report_body, 'text'))

        if args.mispevent:
            part = MIMEBase('application', "octet-stream")
            part.set_payload(attachments['misp_events'])
            part.add_header('Content-Disposition', 'attachment; filename="misp_events.csv"')
            msg.attach(part)

        msg.attach(msg_attach(attachments['attr_type'], 'attr_type.csv'))
        msg.attach(msg_attach(attachments['attr_category'], 'attr_category.csv'))
        msg.attach(msg_attach(attachments['tags_tlp'], 'tags_tlp.csv'))
        msg.attach(msg_attach(attachments['tags_misp_galaxy_mitre'], 'tags_misp_galaxy_mitre.csv'))
        msg.attach(msg_attach(attachments['tags_misp_galaxy'], 'tags_misp_galaxy.csv'))
        msg.attach(msg_attach(attachments['tags_misp_galaxy_threat_actor'], 'tags_misp_galaxy_threat_actor.csv'))
        msg.attach(msg_attach(attachments['tags_type'], 'tags_type.csv'))
        msg.attach(msg_attach(attachments['galaxies'], 'galaxies.csv'))
        msg.attach(msg_attach(attachments['galaxies_cluster'], 'galaxies_cluster.csv'))

        server = smtplib.SMTP(smtp_server)
        server.sendmail(smtp_from, smtp_to, msg.as_string())

    else:
        print(report_body)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate a report of your MISP statistics.')
    parser.add_argument('-t', '--timeframe', required=True, help='Timeframe to include in the report ')
    parser.add_argument('-e', '--mispevent', action='store_true', help='Include MISP event titles')
    parser.add_argument('-m', '--mail', action='store_true', help='Mail the report')
    misp = init(misp_url, misp_key, misp_verifycert)

    args = parser.parse_args()
    timeframe = args.timeframe

    ts_format = '%Y-%m-%d %H:%M:%S'
    threat_levels = ['High', 'Medium', 'Low', 'Undef']
    analysis_completion = ['Initial', 'Ongoing', 'Complete']
    smtp_from = 'INSERT_FROM'
    smtp_to = 'INSERT_TO'
    smtp_server = 'localhost'

    report = get_data(misp, timeframe)
    if(report):
        report_body, attachments = build_report(report, timeframe, misp_url)
        print_report(report_body, attachments, smtp_from, smtp_to, smtp_server, misp_url)
