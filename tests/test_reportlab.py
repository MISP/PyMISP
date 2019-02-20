#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import json
import sys
from io import BytesIO

from pymisp import MISPEvent, MISPSighting, MISPTag, reportlab_generator

class TestMISPEvent(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.mispevent = MISPEvent()
        self.test_folder = "reportlab_testfiles/"
        self.storage_folder = "reportlab_testoutputs/"

    def init_event(self):
        self.mispevent.info = 'This is a test'
        self.mispevent.distribution = 1
        self.mispevent.threat_level_id = 1
        self.mispevent.analysis = 1
        self.mispevent.set_date("2017-12-31")  # test the set date method

    def test_basic_event(self):
        self.init_event()
        reportlab_generator.register_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent), self.storage_folder + "basic_event.pdf")

    def test_event(self):
        self.init_event()
        self.mispevent.load_file(self.test_folder + 'to_delete1.json')
        reportlab_generator.register_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                  self.storage_folder + "basic_event.pdf")

    # TODO : To modify below this line
    def test_loadfile(self):
        self.mispevent.load_file('tests/mispevent_testfiles/event.json')
        with open('tests/mispevent_testfiles/event.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))
