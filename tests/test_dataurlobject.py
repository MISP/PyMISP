#!/usr/bin/env python

from __future__ import annotations

import unittest

from pymisp.tools import DataURLObject


class TestDataURLObject(unittest.TestCase):

    def test_comma_in_data(self) -> None:
        # RFC 2397: only the first comma separates the header from the data,
        # the data itself can contain commas (inline SVG, CSV, ...)
        obj = DataURLObject("data:image/svg+xml;charset=utf-8,<svg><path d='M0,0 L10,10'/></svg>")
        self.assertEqual(obj.get_attributes_by_relation('data')[0].data.getvalue(),
                         b"<svg><path d='M0,0 L10,10'/></svg>")
        self.assertFalse(obj.get_attributes_by_relation('base64')[0].value)
        self.assertEqual(obj.get_attributes_by_relation('media-type')[0].value, 'image/svg+xml')
        self.assertEqual(obj.get_attributes_by_relation('mime-type-parameter')[0].value, 'charset=utf-8')

    def test_base64(self) -> None:
        obj = DataURLObject('data:text/plain;charset=utf-8;base64,aGVsbG8sd29ybGQ=')
        self.assertEqual(obj.get_attributes_by_relation('data')[0].data.getvalue(), b'aGVsbG8sd29ybGQ=')
        self.assertTrue(obj.get_attributes_by_relation('base64')[0].value)
        self.assertEqual(obj.get_attributes_by_relation('media-type')[0].value, 'text/plain')
        self.assertEqual(obj.get_attributes_by_relation('mime-type-parameter')[0].value, 'charset=utf-8')
