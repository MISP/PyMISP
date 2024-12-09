#!/usr/bin/env python3

from __future__ import annotations

from .abstractgenerator import AbstractMISPObjectGenerator


class SBSignatureObject(AbstractMISPObjectGenerator):
    '''
    Sandbox Analyzer
    '''
    def __init__(self, software: str, report: list[tuple[str, str]], **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('sb-signature', **kwargs)
        self._software = software
        self._report = report
        self.generate_attributes()

    def generate_attributes(self) -> None:
        ''' Parse the report for relevant attributes '''
        self.add_attribute("software", value=self._software)
        for (signature_name, description) in self._report:
            self.add_attribute("signature", value=signature_name, comment=description)
