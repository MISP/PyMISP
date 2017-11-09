#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from datetime import date
import importlib

from pymisp import MISPEvent
from defang import defang
from pytaxonomies import Taxonomies


class ReportGenerator():
    def __init__(self, profile="daily_report"):
        self.taxonomies = Taxonomies()
        self.report = ''
        profile_name = "profiles.{}".format(profile)
        self.template = importlib.import_module(name=profile_name)

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
        list_attributes = []
        for attribute in self.misp_event.attributes:
            if attribute.type in self.template.types_to_attach:
                list_attributes.append("* {}".format(defang(attribute.value)))
        for obj in self.misp_event.Object:
            if obj.name in self.template.objects_to_attach:
                for attribute in obj.Attribute:
                    if attribute.type in self.template.types_to_attach:
                        list_attributes.append("* {}".format(defang(attribute.value)))
        return self.template.attributes.format(list_attributes="\n".join(list_attributes))

    def _get_tag_info(self, machinetag):
        return self.taxonomies.revert_machinetag(machinetag)

    def report_headers(self):
        content = {'org_name': 'name',
                   'date': date.today().isoformat()}
        self.report += self.template.headers.format(**content)

    def event_level_tags(self):
        if not self.misp_event.Tag:
            return ''
        for tag in self.misp_event.Tag:
            # Only look for TLP for now
            if tag['name'].startswith('tlp'):
                tax, predicate = self._get_tag_info(tag['name'])
                return self.template.event_level_tags.format(value=predicate.predicate.upper(), expanded=predicate.expanded)

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

        return self.template.title.format(internal_id=internal_id, title=self.misp_event.info,
                                          summary=summary)

    def asciidoc(self, lang='en'):
        self.report += self.title()
        self.report += self.event_level_tags()
        self.report += self.attributes()


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Create a human-readable report out of a MISP event')
        parser.add_argument("--profile", default="daily_report", help="Profile template to use")
        parser.add_argument("-o", "--output", help="Output file to write to (generally ends in .adoc)")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-e", "--event", default=[], nargs='+', help="Event ID to get.")
        group.add_argument("-p", "--path", default=[], nargs='+', help="Path to the JSON dump.")

        args = parser.parse_args()

        report = ReportGenerator(args.profile)
        report.report_headers()

        if args.event:
            for eid in args.event:
                report.from_remote(eid)
                report.asciidoc()
        else:
            for f in args.path:
                report.from_file(f)
                report.asciidoc()

        if args.output:
            with open(args.output, "w") as ofile:
                ofile.write(report.report)
        else:
            print(report.report)
    except ModuleNotFoundError as err:
        print(err)
