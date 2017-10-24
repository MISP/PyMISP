#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import MISPEvent
from defang import defang
import argparse
from pytaxonomies import Taxonomies
from datetime import date

headers = """
:toc: right
:toclevels: 1
:toc-title: Daily Report
:icons: font
:sectanchors:
:sectlinks:
= Daily report by {org_name}
{date}

:icons: font

"""

event_level_tags = """
IMPORTANT: This event is classified TLP:{value}.

{expanded}

"""

attributes = """
=== Indicator(s) of compromise

{list_attributes}

"""

title = """
== ({internal_id}) {title}

{summary}

"""

types_to_attach = ['ip-dst', 'url', 'domain']
objects_to_attach = ['domain-ip']

class ReportGenerator():

    def __init__(self):
        self.taxonomies = Taxonomies()
        self.report = ''

    def from_remote(self, event_id):
        from pymisp import PyMISP
        from keys import misp_url, misp_key, misp_verifycert
        misp = PyMISP(misp_url, misp_key, misp_verifycert)
        result = misp.get(event_id)
        self.misp_event = MISPEvent()
        self.misp_event.load(result)

    def from_file(self, path):
        self.misp_event = MISPEvent()
        self.misp_event.load_file(path)

    def attributes(self):
        if not self.misp_event.attributes:
            return ''
        list_attributes = ''
        for attribute in self.misp_event.attributes:
            if attribute.type in types_to_attach:
                list_attributes += "\n* {}\n".format(defang(attribute.value))
        for obj in self.misp_event.Object:
            for attribute in obj.Attribute:
                if attribute.type in types_to_attach:
                    list_attributes += "\n* {}\n".format(defang(attribute.value))
        return attributes.format(list_attributes=list_attributes)

    def _get_tag_info(self, machinetag):
        return self.taxonomies.revert_machinetag(machinetag)

    def report_headers(self):
        content = {'org_name': 'name',
                   'date': date.today().isoformat()}
        self.report += headers.format(**content)

    def event_level_tags(self):
        if not self.misp_event.Tag:
            return ''
        for tag in self.misp_event.Tag:
            # Only look for TLP for now
            if tag['name'].startswith('tlp'):
                tax, predicate = self._get_tag_info(tag['name'])
                return event_level_tags.format(value=predicate.predicate.upper(), expanded=predicate.expanded)

    def title(self):
        internal_id = ''
        summary = ''
        # Get internal refs for report
        for obj in self.misp_event.Object:
            if obj.name != 'report':
                continue
            for a in obj.Attribute:
                if a.object_relation == 'case-number':
                    internal_id = a.value
                if a.object_relation == 'summary':
                    summary = a.value

        return title.format(internal_id=internal_id, title=self.misp_event.info,
                            summary=summary)


    def asciidoc(self, lang='en'):
        self.report += self.title()
        self.report += self.event_level_tags()
        self.report += self.attributes()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Create a human-readable report out of a MISP event')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--event", default=[], nargs='+', help="Event ID to get.")
    group.add_argument("-p", "--path", default=[], nargs='+', help="Path to the JSON dump.")

    args = parser.parse_args()

    report = ReportGenerator()
    report.report_headers()

    if args.event:
        for eid in args.event:
            report.from_remote(eid)
            report.asciidoc()
    else:
        for f in args.path:
            report.from_file(f)
            report.asciidoc()

    print(report.report)
