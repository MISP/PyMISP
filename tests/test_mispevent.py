#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import json
from io import BytesIO

from pymisp import MISPEvent, MISPSighting


class TestMISPEvent(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.mispevent = MISPEvent()

    def init_event(self):
        self.mispevent.info = 'This is a test'
        self.mispevent.distribution = 1
        self.mispevent.threat_level_id = 1
        self.mispevent.analysis = 1
        self.mispevent.set_date("2017-12-31")  # test the set date method

    def test_simple(self):
        with open('tests/mispevent_testfiles/simple.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_event(self):
        self.init_event()
        self.mispevent.publish()
        with open('tests/mispevent_testfiles/event.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_loadfile(self):
        self.mispevent.load_file('tests/mispevent_testfiles/event.json')
        with open('tests/mispevent_testfiles/event.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_attribute(self):
        self.init_event()
        self.mispevent.add_attribute('filename', 'bar.exe')
        self.mispevent.add_attribute_tag('osint', 'bar.exe')
        attr_tags = self.mispevent.get_attribute_tag('bar.exe')
        self.assertEqual(self.mispevent.attributes[0].tags[0].name, 'osint')
        self.assertEqual(attr_tags[0].name, 'osint')
        with open('tests/mispevent_testfiles/attribute.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))
        # Fake setting an attribute ID for testing
        self.mispevent.attributes[0].id = 42
        self.mispevent.delete_attribute(42)
        with open('tests/mispevent_testfiles/attribute_del.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_object_tag(self):
        self.mispevent.add_object(name='file', strict=True)
        self.mispevent.objects[0].add_attribute('filename', value='bar', Tag=[{'name': 'blah'}])
        self.assertEqual(self.mispevent.objects[0].attributes[0].tags[0].name, 'blah')
        self.assertTrue(self.mispevent.objects[0].has_attributes_by_relation(['filename']))
        self.assertEqual(len(self.mispevent.objects[0].get_attributes_by_relation('filename')), 1)
        self.mispevent.add_object(name='url', strict=True)
        self.mispevent.objects[1].add_attribute('url', value='https://www.circl.lu')
        self.mispevent.objects[0].uuid = 'a'
        self.mispevent.objects[1].uuid = 'b'
        self.mispevent.objects[0].add_reference('b', 'baz', comment='foo')
        self.assertEqual(self.mispevent.objects[0].references[0].relationship_type, 'baz')
        with open('tests/mispevent_testfiles/event_obj_attr_tag.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    @unittest.skip("Not supported on MISP: https://github.com/MISP/MISP/issues/2638 - https://github.com/MISP/PyMISP/issues/168")
    def test_object_level_tag(self):
        self.mispevent.add_object(name='file', strict=True)
        self.mispevent.objects[0].add_attribute('filename', value='bar')
        self.mispevent.objects[0].add_tag('osint')
        self.mispevent.objects[0].uuid = 'a'
        with open('tests/mispevent_testfiles/event_obj_tag.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_malware(self):
        with open('tests/mispevent_testfiles/simple.json', 'rb') as f:
            pseudofile = BytesIO(f.read())
        self.init_event()
        self.mispevent.add_attribute('malware-sample', 'bar.exe', data=pseudofile)
        attribute = self.mispevent.attributes[0]
        self.assertEqual(attribute.malware_binary, pseudofile)
        with open('tests/mispevent_testfiles/malware.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_existing_malware(self):
        self.mispevent.load_file('tests/mispevent_testfiles/malware_exist.json')
        with open('tests/mispevent_testfiles/simple.json', 'rb') as f:
            pseudofile = BytesIO(f.read())
        self.assertEqual(
            self.mispevent.objects[0].get_attributes_by_relation('malware-sample')[0].malware_binary.read(),
            pseudofile.read())

    def test_sighting(self):
        sighting = MISPSighting()
        sighting.from_dict(value='1', type='bar', timestamp=11111111)
        with open('tests/mispevent_testfiles/sighting.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(sighting.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_existing_event(self):
        self.mispevent.load_file('tests/mispevent_testfiles/existing_event.json')
        with open('tests/mispevent_testfiles/existing_event.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_shadow_attributes_existing(self):
        self.mispevent.load_file('tests/mispevent_testfiles/shadow.json')
        with open('tests/mispevent_testfiles/shadow.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_shadow_attributes(self):
        self.init_event()
        self.mispevent.add_proposal(type='filename', value='baz.jpg')
        self.mispevent.add_attribute('filename', 'bar.exe')
        self.mispevent.attributes[0].add_proposal(type='filename', value='bar.pdf')
        with open('tests/mispevent_testfiles/proposals.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))

    def test_default_attributes(self):
        self.mispevent.add_object(name='file', strict=True)
        self.mispevent.objects[0].add_attribute('filename', value='bar', Tag=[{'name': 'blah'}])
        self.mispevent.add_object(name='file', strict=False, default_attributes_parameters=self.mispevent.objects[0].attributes[0])
        self.mispevent.objects[1].add_attribute('filename', value='baz')
        self.mispevent.objects[0].uuid = 'a'
        self.mispevent.objects[1].uuid = 'b'
        with open('tests/mispevent_testfiles/event_obj_def_param.json', 'r') as f:
            ref_json = json.load(f)
        self.assertEqual(self.mispevent.to_json(), json.dumps(ref_json, sort_keys=True, indent=2))


if __name__ == '__main__':
    unittest.main()
