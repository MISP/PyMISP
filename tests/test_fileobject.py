#!/usr/bin/env python

from __future__ import annotations

import unittest
import json
from pymisp.tools import FileObject
import pathlib


class TestFileObject(unittest.TestCase):
    def test_mimeType(self) -> None:
        file_object = FileObject(filepath=pathlib.Path(__file__))
        attributes = json.loads(file_object.to_json())['Attribute']
        mime = next(attr for attr in attributes if attr['object_relation'] == 'mimetype')
        # was "Python script, ASCII text executable"
        # libmagic on linux: 'text/x-python'
        # libmagic on os x:  'text/x-script.python'
        self.assertEqual(mime['value'][:7], 'text/x-')
        self.assertEqual(mime['value'][-6:], 'python')
