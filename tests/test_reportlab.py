#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from pymisp import MISPEvent

from pymisp.tools import reportlab_generator

import os
import sys

class TestMISPEvent(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.mispevent = MISPEvent()
        self.test_folder = "tests/reportlab_testfiles/" #tests/
        self.test_batch_folder = "tests/OSINT_output/"
        self.storage_folder = "tests/reportlab_testoutputs/"

    def init_event(self):
        self.mispevent.info = 'This is a test'
        self.mispevent.distribution = 1
        self.mispevent.threat_level_id = 1
        self.mispevent.analysis = 1
        self.mispevent.set_date("2017-12-31")  # test the set date method

    def check_python_2(self):
        if sys.version_info.major < 3:
            # we want Python2 test to pass
            assert(True)

    def test_basic_event(self):
        self.check_python_2()
        self.init_event()
        reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent), self.storage_folder + "basic_event.pdf")

    def test_event(self):
        self.check_python_2()
        self.init_event()
        self.mispevent.load_file(self.test_folder + 'to_delete1.json')
        reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                  self.storage_folder + "basic_event.pdf")

    def test_HTML_json(self):
        self.check_python_2()
        self.init_event()
        self.mispevent.load_file(self.test_folder + '56e12e66-f01c-41be-afea-4d9a950d210f.json')
        reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                  self.storage_folder + "HTML.pdf")

    def test_long_json(self):
        self.check_python_2()
        self.init_event()
        self.mispevent.load_file(self.test_folder + '57153590-f73c-49fa-be4b-4737950d210f.json')
        reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                  self.storage_folder + "Very_long.pdf")
        # Issue report : "We are not smart enough" : https://pairlist2.pair.net/pipermail/reportlab-users/2010-May/009529.html
        # Not nice but working solution exposed ther e: https://pairlist2.pair.net/pipermail/reportlab-users/2016-March/011525.html

    def test_very_long_json(self):
        self.check_python_2()
        self.init_event()
        self.mispevent.load_file(self.test_folder + '5abf6421-c1b8-477b-a9d2-9c0902de0b81.json')
        reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                  self.storage_folder + "super_long.pdf")
