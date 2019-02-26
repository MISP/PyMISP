#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from pymisp import MISPEvent

from pymisp.tools import reportlab_generator

import sys
import os
import time

manual_testing = True

class TestMISPEvent(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.mispevent = MISPEvent()
        if not manual_testing :
            self.root = "tests/"
        else :
            self.root = ""
        self.test_folder = self.root + "reportlab_testfiles/"
        self.test_batch_folder = self.root + "OSINT_output/"
        self.storage_folder = self.root + "reportlab_testoutputs/"

    def init_event(self):
        self.mispevent.info = 'This is a test'
        self.mispevent.distribution = 1
        self.mispevent.threat_level_id = 1
        self.mispevent.analysis = 1
        self.mispevent.set_date("2017-12-31")  # test the set date method

    def check_python_2(self):
        if sys.version_info.major < 3:
            # we want Python2 test to pass
            return True

    def test_basic_event(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:
            self.init_event()
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                       self.storage_folder + "basic_event.pdf")

    def test_event(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:
            self.init_event()
            self.mispevent.load_file(self.test_folder + 'to_delete1.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                       self.storage_folder + "basic_event.pdf")

    def test_HTML_json(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:
            self.init_event()
            self.mispevent.load_file(self.test_folder + '56e12e66-f01c-41be-afea-4d9a950d210f.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                       self.storage_folder + "HTML.pdf")

    def test_long_json(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:
            self.init_event()
            self.mispevent.load_file(self.test_folder + '57153590-f73c-49fa-be4b-4737950d210f.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                       self.storage_folder + "long.pdf")
            # Issue report : "We are not smart enough" : https://pairlist2.pair.net/pipermail/reportlab-users/2010-May/009529.html
            # Not nice but working solution exposed ther e: https://pairlist2.pair.net/pipermail/reportlab-users/2016-March/011525.html

    def test_very_long_json(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:
            self.init_event()
            self.mispevent.load_file(self.test_folder + '5abf6421-c1b8-477b-a9d2-9c0902de0b81.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                                                       self.storage_folder + "very_long.pdf")

    def test_full_config_json(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:

            config = {}
            moduleconfig = ["MISP_base_url_for_dynamic_link", "MISP_name_for_metadata"]
            config[moduleconfig[0]] = "http://localhost:8080"
            config[moduleconfig[1]] =  "My Wonderful CERT"

            self.init_event()
            self.mispevent.load_file(self.test_folder + '5abf6421-c1b8-477b-a9d2-9c0902de0b81.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent, config),
                                                       self.storage_folder + "config_complete.pdf")

    def test_partial_0_config_json(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:

            config = {}
            moduleconfig = ["MISP_base_url_for_dynamic_link", "MISP_name_for_metadata"]
            config[moduleconfig[0]] = "http://localhost:8080"

            self.init_event()
            self.mispevent.load_file(self.test_folder + '5abf6421-c1b8-477b-a9d2-9c0902de0b81.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent, config),
                                                       self.storage_folder + "config_partial_0.pdf")

    def test_partial_1_config_json(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:

            config = {}
            moduleconfig = ["MISP_base_url_for_dynamic_link", "MISP_name_for_metadata"]
            config[moduleconfig[1]] =  "My Wonderful CERT"

            self.init_event()
            self.mispevent.load_file(self.test_folder + '5abf6421-c1b8-477b-a9d2-9c0902de0b81.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent, config),
                                                       self.storage_folder + "config_partial_1.pdf")

    def test_image_json(self):
        if self.check_python_2():
            self.assertTrue(True)
        else:

            config = {}
            moduleconfig = ["MISP_base_url_for_dynamic_link", "MISP_name_for_metadata"]
            config[moduleconfig[0]] = "http://localhost:8080"
            config[moduleconfig[1]] =  "My Wonderful CERT"

            self.init_event()
            self.mispevent.load_file(self.test_folder + 'image_event.json')
            reportlab_generator.register_value_to_file(reportlab_generator.convert_event_in_pdf_buffer(self.mispevent, config),
                                                       self.storage_folder + "image_event.pdf")

    def test_batch_OSINT_events(self):
        # Test case ONLY for manual testing. Needs to download a full list of OSINT events !

        if self.check_python_2():
            self.assertTrue(True)
        elif not manual_testing :
            self.assertTrue(True)
        else:
            self.init_event()

            file_nb = str(len(os.listdir(self.test_batch_folder)))
            i = 0
            t = time.time()
            for curr_file in os.listdir(self.test_batch_folder):
                self.mispevent = MISPEvent()
                file_path = self.test_batch_folder + curr_file

                print("Current file : " + file_path + " " + str(i) + " over " + file_nb)
                i += 1

                self.mispevent.load_file(file_path)

                reportlab_generator.register_value_to_file(
                    reportlab_generator.convert_event_in_pdf_buffer(self.mispevent),
                    self.storage_folder + curr_file + ".pdf")
            print("Elapsed time : " + str(time.time() - t))
            # Local run : 1958.930s for 1064 files
