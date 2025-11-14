#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Koen Van Impe
Maxime Thiebaut

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
from datetime import date
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


def get_data(misp, timeframe, date_from=None, date_to=None):
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
        if date_from and date_to:
            stats_event_response = misp.search(date_from=date_from, date_to=date_to)
        else:
            stats_event_response = misp.search(last=timeframe)

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
        report['number_of_attributes'] = number_of_attributes
        report['number_of_attributes_to_ids'] = number_of_attributes_to_ids
        report['attr_type'] = attr_type
        report['attr_category'] = attr_category
        report['tags_type'] = tags_type
        report['tags_tlp'] = tags_tlp
        report['tags_misp_galaxy_mitre'] = tags_misp_galaxy_mitre
        report['tags_misp_galaxy'] = tags_misp_galaxy
        report['tags_misp_galaxy_threat_actor'] = tags_misp_galaxy_threat_actor
        report['galaxies'] = galaxies
        report['galaxies_cluster'] = galaxies_cluster

        # General MISP statistics
        user_statistics = misp.users_statistics()
        if user_statistics and 'errors' not in user_statistics:
            report['user_statistics'] = user_statistics

        # Return the report data
        return report
    except Exception as e:
        sys.exit('Unable to get statistics from MISP')


def build_report(report, timeframe, misp_url, sanitize_report=True):
    '''
        Build the body of the report and optional attachments
    '''
    attachments = {}

    now = datetime.now()
    current_date = now.strftime(ts_format)
    if timeframe:
        report_body = "MISP Report %s for last %s on %s\n-------------------------------------------------------------------------------" % (current_date, timeframe, misp_url)
    else:
        report_body = "MISP Report %s from %s to %s on %s\n-------------------------------------------------------------------------------" % (current_date, date_from, date_to, misp_url)

    report_body = report_body + '\nNew or updated events: %s' % report['number_of_misp_events']
    report_body = report_body + '\nNew or updated attributes: %s' % report['number_of_attributes']
    report_body = report_body + '\nNew or updated attributes with IDS flag: %s' % report['number_of_attributes_to_ids']
    report_body = report_body + '\n'
    if 'user_statistics' in report:
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
            report_body = report_body + '\n #%s %s (%s) \t%s \n\t\t\t\t(Date: %s, Updated: %s, Published: %s)' % (el['id'], el['threat_level'], el['analysis_completion'], el['title'].decode('utf-8'), el['date'], el['timestamp'], el['publish_timestamp'])
            attachments['misp_events'] = attachments['misp_events'] + '\n%s;%s;%s;%s;%s;%s;%s' % (el['id'], el['title'].decode('utf-8'), el['date'], el['timestamp'], el['publish_timestamp'], el['threat_level'], el['analysis_completion'])

    report_body, attachments['attr_category'] = add_report_body(report_body, 'New or updated attributes - Category', report['attr_category'], 'AttributeCategory;Qt')
    report_body, attachments['attr_type'] = add_report_body(report_body, 'New or updated attributes - Type', report['attr_type'], 'AttributeType;Qt')
    report_body, attachments['tags_tlp'] = add_report_body(report_body, 'TLP Codes', report['tags_tlp'], 'TLP;Qt')
    report_body, attachments['tags_misp_galaxy'] = add_report_body(report_body, 'Tag MISP Galaxy', report['tags_misp_galaxy'], 'MISPGalaxy;Qt')
    report_body, attachments['tags_misp_galaxy_mitre'] = add_report_body(report_body, 'Tag MISP Galaxy Mitre', report['tags_misp_galaxy_mitre'], 'MISPGalaxyMitre;Qt')
    report_body, attachments['tags_misp_galaxy_threat_actor'] = add_report_body(report_body, 'Tag MISP Galaxy Threat Actor', report['tags_misp_galaxy_threat_actor'], 'MISPGalaxyThreatActor;Qt')
    report_body, attachments['tags_type'] = add_report_body(report_body, 'Tags', report['tags_type'], 'Tag;Qt')
    report_body, attachments['galaxies'] = add_report_body(report_body, 'Galaxies', report['galaxies'], 'Galaxies;Qt')
    report_body, attachments['galaxies_cluster'] = add_report_body(report_body, 'Galaxies Cluster', report['galaxies_cluster'], 'Galaxies;Qt')

    if sanitize_report:
        mitre_tactic = get_sanitized_report(report['tags_misp_galaxy_mitre'], 'ATT&CK Tactic')
        mitre_group = get_sanitized_report(report['tags_misp_galaxy_mitre'], 'ATT&CK Group')
        mitre_software = get_sanitized_report(report['tags_misp_galaxy_mitre'], 'ATT&CK Software')
        threat_actor = get_sanitized_report(report['tags_misp_galaxy_threat_actor'], 'MISP Threat Actor')
        misp_tag = get_sanitized_report(report['tags_type'], 'MISP Tags', False, True)

        report_body, attachments['mitre_tactics'] = add_report_body(report_body, 'MITRE ATT&CK Tactics (sanitized)', mitre_tactic, 'MITRETactics;Qt')
        report_body, attachments['mitre_group'] = add_report_body(report_body, 'MITRE ATT&CK Group (sanitized)', mitre_group, 'MITREGroup;Qt')
        report_body, attachments['mitre_software'] = add_report_body(report_body, 'MITRE ATT&CK Software (sanitized)', mitre_software, 'MITRESoftware;Qt')
        report_body, attachments['threat_actor'] = add_report_body(report_body, 'MISP Threat Actor (sanitized)', threat_actor, 'MISPThreatActor;Qt')
        report_body, attachments['misp_tag'] = add_report_body(report_body, 'Tags (sanitized)', misp_tag, 'MISPTags;Qt')

    report_body = report_body + "\n\nMISP Reporter Finished\n"

    return report_body, attachments


def add_report_body(report_body, subtitle, data_object, csv_title):
    '''
        Add a section to the report body text
    '''
    if report_body:
        report_body = report_body + '\n\n'
        report_body = report_body + '\n%s\n-------------------------------------------------------------------------------' % subtitle
        data_object_s = sorted(data_object.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
        csv_attachment = csv_title
        for el in data_object_s:
            report_body = report_body + "\n%s \t %s" % (el[0], el[1])
            csv_attachment = csv_attachment + '\n%s;%s' % (el[0], el[1])

        return report_body, csv_attachment


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

        if timeframe:
            subject = "MISP Report %s for last %s on %s" % (current_date, timeframe, misp_url)
        else:
            subject = "MISP Report %s from %s to %s on %s" % (current_date, date_from, date_to, misp_url)

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
        msg.attach(msg_attach(attachments['misp_tag'], 'misp_tag.csv'))
        msg.attach(msg_attach(attachments['threat_actor'], 'threat_actor.csv'))
        msg.attach(msg_attach(attachments['mitre_software'], 'mitre_software.csv'))
        msg.attach(msg_attach(attachments['mitre_group'], 'mitre_group.csv'))
        msg.attach(msg_attach(attachments['mitre_tactics'], 'mitre_tactics.csv'))

        server = smtplib.SMTP(smtp_server)
        server.sendmail(smtp_from, smtp_to, msg.as_string())

    else:
        print(report_body)


def get_sanitized_report(dataset, sanitize_selector='ATT&CK Tactic', lower=False, add_not_sanitized=False):
    '''
        Remove or bundle some of the tags
            'quick'n'dirty ; could also do this by using the galaxy/tags definition
    '''
    # If you add the element completely then it gets removed by an empty string; this allows to filter out non-relevant items
    sanitize_set = {
                    'ATT&CK Tactic': ['misp-galaxy:mitre-enterprise-attack-pattern="', 'misp-galaxy:mitre-pre-attack-pattern="', 'misp-galaxy:mitre-mobile-attack-pattern="', 'misp-galaxy:mitre-attack-pattern="', 'misp-galaxy:mitre-enterprise-attack-attack-pattern="', 'misp-galaxy:mitre-pre-attack-attack-pattern="', 'misp-galaxy:mitre-enterprise-attack-attack-pattern="', 'misp-galaxy:mitre-mobile-attack-attack-pattern="'],
                    'ATT&CK Group': ['misp-galaxy:mitre-enterprise-intrusion-set="', 'misp-galaxy:mitre-pre-intrusion-set="', 'misp-galaxy:mitre-mobile-intrusion-set="', 'misp-galaxy:mitre-intrusion-set="', 'misp-galaxy:mitre-enterprise-attack-intrusion-set="', 'misp-galaxy:mitre-pre-attack-intrusion-set="', 'misp-galaxy:mitre-mobile-attack-intrusion-set="'],
                    'ATT&CK Software': ['misp-galaxy:mitre-enterprise-malware="', 'misp-galaxy:mitre-pre-malware="', 'misp-galaxy:mitre-mobile-malware="', 'misp-galaxy:mitre-malware="', 'misp-galaxy:mitre-enterprise-attack-tool="', 'misp-galaxy:mitre-enterprise-tool="', 'misp-galaxy:mitre-pre-tool="', 'misp-galaxy:mitre-mobile-tool="', 'misp-galaxy:mitre-tool="', 'misp-galaxy:mitre-enterprise-attack-malware="'],
                    'MISP Threat Actor': ['misp-galaxy:threat-actor="'],
                    'MISP Tags': ['circl:incident-classification="', 'osint:source-type="blog-post"', 'misp-galaxy:tool="', 'CERT-XLM:malicious-code="', 'circl:topic="', 'ddos:type="', 'ecsirt:fraud="', 'dnc:malware-type="', 'enisa:nefarious-activity-abuse="', 'europol-incident:information-gathering="', 'misp-galaxy:ransomware="', 'misp-galaxy:rat="', 'misp-galaxy:social-dark-patterns="', 'misp-galaxy:tool="', 'misp:threat-level="', 'ms-caro-malware:malware-platform=', 'ms-caro-malware:malware-type=', 'veris:security_incident="', 'veris:attribute:integrity:variety="', 'veris:actor:motive="', 'misp-galaxy:banker="', 'misp-galaxy:malpedia="', 'misp-galaxy:botnet="', 'malware_classification:malware-category="', 'TLP: white', 'TLP: Green',
                    'inthreat:event-src="feed-osint"', 'tlp:white', 'tlp:amber', 'tlp:green', 'tlp:red', 'osint:source-type="blog-post"', 'Partner Feed', 'IBM XForce', 'type:OSINT', 'malware:', 'osint:lifetime="perpetual"', 'Actor:', 'osint:certainty="50"', 'Banker:', 'Group:', 'Threat:',
                    'ncsc-nl-ndn:feed="selected"', 'misp-galaxy:microsoft-activity-group="', 'admiralty-scale:source-reliability="b"', 'admiralty-scale:source-reliability="a"', 'admiralty-scale:information-credibility="2"', 'admiralty-scale:information-credibility="3"',
                    'feed:source="CESICAT"', 'osint:source-type="automatic-analysis"', 'workflow:state="complete"', 'osint:source-type="technical-report"',
                    'csirt_case_classification:incident-category="', 'dnc:driveby-type="', 'veris:action:social:variety="', 'osint:source-type="',
                    'osint:source-type="microblog-post"', 'ecsirt:malicious-code="', 'misp-galaxy:sector="', 'veris:action:variety=', 'label=', 'csirt_case_classification:incident-category="', 'admiralty-scale:source-reliability="c"', 'workflow:todo="review"', 'LDO-CERT:detection="toSIEM"', 'Threat tlp:White', 'Threat Type:', 'adversary:infrastructure-state="active"', 'cirl:incident-classification:', 'misp-galaxy:android="', 'dnc:infrastructure-type="', 'ecsirt:information-gathering="', 'ecsirt:intrusions="', 'dhs-ciip-sectors:DHS-critical-sectors="', 'malware_classification:obfuscation-technique="no-obfuscation"',
                    'riskiq:threat-type="', 'veris:action:hacking:variety="', 'veris:action:social:target="', 'workflow:state="incomplete"', 'workflow:todo="add-tagging"', 'workflow:todo="add-context"', 'europol-incident:availability="', 'label=', 'misp-galaxy:stealer="',  'misp-galaxy:exploit-kit="', 'rsit:availability="', 'rsit:fraud="', 'ransomware:type="', 'veris:action:variety=', 'malware:',
                    'ecsirt:abusive-content="']}
    if sanitize_selector == 'MISP Tags':
        sanitize_set['MISP Tags'] = sanitize_set['MISP Tags'] + sanitize_set['ATT&CK Tactic'] + sanitize_set['ATT&CK Group'] + sanitize_set['ATT&CK Software'] + sanitize_set['MISP Threat Actor']
    result_sanitize_set = {}

    if dataset:
        for element in dataset:
            sanited = False
            for sanitize_el in sanitize_set[sanitize_selector]:
                if sanitize_el in element:
                    sanited = True
                    new_el = element.replace(sanitize_el, '').replace('"', '').strip()
                    if lower:
                        new_el = new_el.lower()
                    result_sanitize_set[new_el] = dataset[element]
            if add_not_sanitized and not sanited:
                new_el = element.strip()
                if lower:
                    new_el = new_el.lower()
                result_sanitize_set[new_el] = dataset[element]

    return result_sanitize_set


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate a report of your MISP statistics.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--timeframe', action='store', help='Timeframe to include in the report')
    group.add_argument('-f', '--date_from', action='store', help='Start date of query (YYYY-MM-DD)')
    parser.add_argument('-u', '---date-to', action='store', help='End date of query (YYYY-MM-DD)')
    parser.add_argument('-e', '--mispevent', action='store_true', help='Include MISP event titles')
    parser.add_argument('-m', '--mail', action='store_true', help='Mail the report')
    parser.add_argument('-o', '--mailoptions', action='store', help='mailoptions: \'smtp_from=INSERT_FROM;smtp_to=INSERT_TO;smtp_server=localhost\'')

    args = parser.parse_args()
    misp = init(misp_url, misp_key, misp_verifycert)

    timeframe = args.timeframe
    if not timeframe:
        date_from = args.date_from
        if not args.date_to:
            today = date.today()
            date_to = today.strftime("%Y-%m-%d")
        else:
            date_to = args.date_to
    else:
        date_from = None
        date_to = None

    ts_format = '%Y-%m-%d %H:%M:%S'
    threat_levels = ['High', 'Medium', 'Low', 'Undef']
    analysis_completion = ['Initial', 'Ongoing', 'Complete']
    smtp_from = 'INSERT_FROM'
    smtp_to = 'INSERT_TO'
    smtp_server = 'localhost'

    if args.mailoptions:
        mailoptions = args.mailoptions.split(';')
        for s in mailoptions:
            if s.split('=')[0] == 'smtp_from':
                smtp_from = s.split('=')[1]
            if s.split('=')[0] == 'smtp_to':
                smtp_to = s.split('=')[1]
            if s.split('=')[0] == 'smtp_server':
                smtp_server = s.split('=')[1]

    report = get_data(misp, timeframe, date_from, date_to)
    if(report):
        report_body, attachments = build_report(report, timeframe, misp_url)
        print_report(report_body, attachments, smtp_from, smtp_to, smtp_server, misp_url)
