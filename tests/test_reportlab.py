#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from pymisp import MISPEvent

from pymisp.tools import reportlab_generator

import os


class TestMISPEvent(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.mispevent = MISPEvent()
        self.test_folder = "tests/reportlab_testfiles/"
        self.storage_folder = "tests/reportlab_testoutputs/"

    def init_event(self):
        self.mispevent.info = 'This is a test'
        self.mispevent.distribution = 1
        self.mispevent.threat_level_id = 1
        self.mispevent.analysis = 1
        self.mispevent.set_date("2017-12-31")  # test the set date method

    def test_basic_event(self):
        self.init_event()
        reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent), self.storage_folder + "basic_event.pdf")

    def test_event(self):
        self.init_event()
        self.mispevent.load_file(self.test_folder + 'to_delete1.json')
        reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                  self.storage_folder + "basic_event.pdf")

    def test_batch_OSNT_events(self):
        self.init_event()

        file_nb = str(len(os.listdir(self.test_folder)))
        i = 0

        for curr_file in os.listdir(self.test_folder):
            self.mispevent = MISPEvent()
            file_path = self.test_folder + curr_file

            print("Current file : " + file_path + " " + str(i) + " over " + file_nb)
            i += 1

            self.mispevent.load_file(file_path)

            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                 self.storage_folder + curr_file + ".pdf")
