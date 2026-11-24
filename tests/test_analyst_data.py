#!/usr/bin/env python

from __future__ import annotations

import unittest
from pymisp import (MISPAttribute, MISPEvent, MISPEventReport, MISPNote,
                    MISPObject, MISPOpinion, MISPRelationship, value_sha256)
from pymisp.exceptions import NewAnalystDataError, NewRelationshipError
from uuid import uuid4


class TestAnalystData(unittest.TestCase):
    def setUp(self) -> None:
        self.note_dict = {
            "uuid": uuid4(),
            "note": "note3"
        }
        self.opinion_dict = {
            "uuid": uuid4(),
            "opinion": 75,
            "comment": "Agree"
        }

    def test_analyst_data_on_attribute(self) -> None:
        attribute = MISPAttribute()
        attribute.from_dict(type='filename', value='foo.exe')
        self._attach_analyst_data(attribute)

    def test_analyst_data_on_attribute_alternative(self) -> None:
        event = MISPEvent()
        event.info = 'Test on Attribute'
        event.add_attribute('domain', 'foo.bar')
        self._attach_analyst_data(event.attributes[0])

    def test_analyst_data_on_event(self) -> None:
        event = MISPEvent()
        event.info = 'Test Event'
        self._attach_analyst_data(event)

    def test_analyst_data_on_event_report(self) -> None:
        event_report = MISPEventReport()
        event_report.from_dict(name='Test Report', content='This is a report')
        self._attach_analyst_data(event_report)

    def test_analyst_data_on_event_report_alternative(self) -> None:
        event = MISPEvent()
        event.info = 'Test on Event Report'
        event.add_event_report('Test Report', 'This is a report')
        self._attach_analyst_data(event.event_reports[0])

    def test_analyst_data_on_object(self) -> None:
        misp_object = MISPObject('file')
        misp_object.add_attribute('filename', 'foo.exe')
        self._attach_analyst_data(misp_object)

    def test_analyst_data_on_object_alternative(self) -> None:
        event = MISPEvent()
        event.info = 'Test on Object'
        misp_object = MISPObject('file')
        misp_object.add_attribute('filename', 'foo.exe')
        event.add_object(misp_object)
        self._attach_analyst_data(event.objects[0])

    def test_analyst_data_on_object_attribute(self) -> None:
        misp_object = MISPObject('file')
        object_attribute = misp_object.add_attribute('filename', 'foo.exe')
        self._attach_analyst_data(object_attribute)

    def test_analyst_data_object_object_attribute_alternative(self) -> None:
        misp_object = MISPObject('file')
        misp_object.add_attribute('filename', 'foo.exe')
        self._attach_analyst_data(misp_object.attributes[0])

    def test_value_sha256(self) -> None:
        self.assertEqual(value_sha256('tftp://213.21.117.191/.i'),
                         '3cbad7bc936718f07fa8665bc64ce46986142bea60f86fd0c05cd2a4a8ea2bc4')

    def test_note_on_value(self) -> None:
        address = value_sha256('evil.com')
        note = MISPNote(note='Seen in campaign X', object_type='AttributeValue',
                        object_sha256=f' {address.upper()} ')
        self.assertEqual(note.object_sha256, address)
        self.assertIsNone(note.object_uuid)
        exported = note.to_dict()
        self.assertEqual(exported['object_sha256'], address)
        self.assertNotIn('object_uuid', exported)

    def test_value_target_needs_a_valid_hash(self) -> None:
        with self.assertRaises(NewAnalystDataError):
            MISPNote(note='x', object_type='AttributeValue')
        with self.assertRaises(NewAnalystDataError):
            MISPNote(note='x', object_type='AttributeValue', object_sha256='not-a-hash')
        with self.assertRaises(NewAnalystDataError):
            MISPNote(note='x', object_type='Event', object_uuid=str(uuid4()),
                     object_sha256=value_sha256('evil.com'))

    def test_analyst_data_as_misp_3_returns_it(self) -> None:
        address = value_sha256('evil.com')
        on_value = MISPOpinion()
        on_value.from_dict(Opinion={
            'uuid': str(uuid4()), 'opinion': '70', 'comment': 'x', 'distribution': '3',
            'object_type': 'AttributeValue', 'object_uuid': None, 'object_sha256': address,
            'created': '2026-10-16 08:34:49', 'modified': '2026-10-16 08:34:49'})
        self.assertEqual(on_value.object_sha256, address)
        on_event = MISPNote()
        event_uuid = str(uuid4())
        on_event.from_dict(Note={
            'uuid': str(uuid4()), 'note': 'x', 'distribution': '3', 'object_type': 'Event',
            'object_uuid': event_uuid, 'object_sha256': None})
        self.assertEqual(on_event.object_uuid, event_uuid)
        self.assertNotIn('object_sha256', on_event.to_dict())

    def test_relationship_to_value(self) -> None:
        attribute = MISPAttribute()
        attribute.from_dict(type='domain', value='evil.com')
        address = value_sha256(attribute.value)
        relationship = attribute.add_relationship('AttributeValue', None, 'related-to',
                                                  related_object_sha256=address)
        self.assertEqual(relationship.object_uuid, attribute.uuid)
        self.assertEqual(relationship.related_object_sha256, address)
        self.assertIsNone(relationship.related_object_uuid)
        with self.assertRaises(NewRelationshipError):
            attribute.add_relationship('AttributeValue', None, 'related-to')
        with self.assertRaises(NewRelationshipError):
            attribute.add_relationship('Attribute', str(uuid4()), 'related-to',
                                       related_object_sha256=address)

    def test_relationship_from_value(self) -> None:
        event_uuid = str(uuid4())
        relationship = MISPRelationship(
            object_type='AttributeValue', object_sha256=value_sha256('evil.com'),
            related_object_type='Event', related_object_uuid=event_uuid,
            relationship_type='seen-in')
        self.assertIsNone(relationship.object_uuid)
        self.assertEqual(relationship.related_object_uuid, event_uuid)

    def test_event_nesting_a_relationship_to_value(self) -> None:
        # MISP 3.0 nests an attribute's relationship to a value under the attribute
        address = value_sha256('evil.com')
        attribute_uuid = str(uuid4())
        event = MISPEvent()
        event.load({'Event': {'info': 'Test', 'Attribute': [{
            'uuid': attribute_uuid, 'type': 'domain', 'value': 'evil.com',
            'Relationship': [{
                'uuid': str(uuid4()), 'distribution': '3', 'relationship_type': 'related-to',
                'object_type': 'Attribute', 'object_uuid': attribute_uuid, 'object_sha256': None,
                'related_object_type': 'AttributeValue', 'related_object_uuid': None,
                'related_object_sha256': address}]}]}})
        relationship = event.attributes[0].relationships[0]
        self.assertEqual(relationship.related_object_sha256, address)
        self.assertEqual(relationship.object_uuid, attribute_uuid)

    def _attach_analyst_data(
            self, container: MISPAttribute | MISPEvent | MISPEventReport | MISPObject) -> None:
        object_type = container._analyst_data_object_type
        note1 = container.add_note(note='note1')
        opinion1 = note1.add_opinion(opinion=25, comment='Disagree')
        opinion2 = container.add_opinion(opinion=50, comment='Neutral')
        note2 = opinion2.add_note(note='note2')

        dict_note = MISPNote()
        dict_note.from_dict(
            object_type=object_type, object_uuid=container.uuid, **self.note_dict
        )
        note3 = container.add_note(**dict_note)
        dict_opinion = MISPOpinion()
        dict_opinion.from_dict(
            object_type='Note', object_uuid=note3.uuid, **self.opinion_dict
        )
        container.add_opinion(**dict_opinion)

        self.assertEqual(len(container.notes), 3)
        self.assertEqual(len(container.opinions), 3)

        misp_note1, misp_note2, misp_note3 = container.notes
        misp_opinion1, misp_opinion2, misp_opinion3 = container.opinions

        self.assertEqual(misp_note1.object_type, object_type)
        self.assertEqual(misp_note1.object_uuid, container.uuid)
        self.assertEqual(misp_note1.note, 'note1')

        self.assertEqual(misp_note2.object_type, 'Opinion')
        self.assertEqual(misp_note2.object_uuid, opinion2.uuid)
        self.assertEqual(misp_note2.note, 'note2')

        self.assertEqual(misp_note3.object_type, object_type)
        self.assertEqual(misp_note3.object_uuid, container.uuid)
        self.assertEqual(misp_note3.note, 'note3')

        self.assertEqual(misp_opinion1.object_type, 'Note')
        self.assertEqual(misp_opinion1.object_uuid, note1.uuid)
        self.assertEqual(misp_opinion1.opinion, 25)
        self.assertEqual(misp_opinion1.comment, 'Disagree')

        self.assertEqual(misp_opinion2.object_type, object_type)
        self.assertEqual(misp_opinion2.object_uuid, container.uuid)
        self.assertEqual(misp_opinion2.opinion, 50)
        self.assertEqual(misp_opinion2.comment, 'Neutral')

        self.assertEqual(misp_opinion3.object_type, 'Note')
        self.assertEqual(misp_opinion3.object_uuid, note3.uuid)
        self.assertEqual(misp_opinion3.opinion, 75)
        self.assertEqual(misp_opinion3.comment, 'Agree')
