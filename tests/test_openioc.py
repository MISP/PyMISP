#!/usr/bin/env python

from __future__ import annotations

import unittest
import warnings

from pymisp.tools import openioc

try:
    from bs4 import XMLParsedAsHTMLWarning  # type: ignore
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass


# Two children of an AND-indicator whose combined search-context pair is NOT a
# defined composite (RegistryItem/Value + FileItem/Md5sum). These must come back
# as their two individual attributes, not a merged composite.
NON_COMPOSITE = """<?xml version="1.0" encoding="us-ascii"?>
<ioc xmlns="http://schemas.mandiant.com/2010/ioc">
  <short_description>non-composite test</short_description>
  <definition>
    <Indicator operator="AND" id="ind-1">
      <IndicatorItem id="a" condition="is">
        <Context document="RegistryItem" search="RegistryItem/Value" type="mir"/>
        <Content type="string">malicious_value</Content>
      </IndicatorItem>
      <IndicatorItem id="b" condition="is">
        <Context document="FileItem" search="FileItem/Md5sum" type="mir"/>
        <Content type="md5">d41d8cd98f00b204e9800998ecf8427e</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>"""

# A genuine, defined composite pair (FileItem/FileName + FileItem/Md5sum). This
# must still merge into a single filename|md5 attribute.
COMPOSITE = """<?xml version="1.0" encoding="us-ascii"?>
<ioc xmlns="http://schemas.mandiant.com/2010/ioc">
  <short_description>composite test</short_description>
  <definition>
    <Indicator operator="AND" id="ind-2">
      <IndicatorItem id="a" condition="is">
        <Context document="FileItem" search="FileItem/FileName" type="mir"/>
        <Content type="string">evil.exe</Content>
      </IndicatorItem>
      <IndicatorItem id="b" condition="is">
        <Context document="FileItem" search="FileItem/Md5sum" type="mir"/>
        <Content type="md5">d41d8cd98f00b204e9800998ecf8427e</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>"""


class TestOpenIOC(unittest.TestCase):

    def test_non_composite_and_indicator_not_merged(self) -> None:
        event = openioc.load_openioc(NON_COMPOSITE)
        by_type = {attr.type: attr.value for attr in event.attributes}
        # Two distinct, correctly typed attributes, no bogus merged composite.
        self.assertEqual(len(event.attributes), 2)
        self.assertEqual(by_type.get('regkey'), 'malicious_value')
        self.assertEqual(by_type.get('md5'), 'd41d8cd98f00b204e9800998ecf8427e')
        self.assertNotIn('other', by_type)

    def test_genuine_composite_still_merged(self) -> None:
        event = openioc.load_openioc(COMPOSITE)
        self.assertEqual(len(event.attributes), 1)
        attr = event.attributes[0]
        self.assertEqual(attr.type, 'filename|md5')
        self.assertEqual(attr.value, 'evil.exe|d41d8cd98f00b204e9800998ecf8427e')


if __name__ == '__main__':
    unittest.main()
