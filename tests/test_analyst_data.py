#!/usr/bin/env python

from __future__ import annotations

import unittest
from pymisp import (MISPAttribute, MISPEvent, MISPEventReport, MISPNote,
                    MISPObject, MISPOpinion)
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
