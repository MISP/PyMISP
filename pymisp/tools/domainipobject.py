#!/usr/bin/env python

from __future__ import annotations

import logging

from typing import Any

from .abstractgenerator import AbstractMISPObjectGenerator

logger = logging.getLogger('pymisp')


class DomainIPObject(AbstractMISPObjectGenerator):

    def __init__(self, parameters: dict[str, Any], strict: bool = True, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('domain-ip', strict=strict, **kwargs)
        self._parameters = parameters
        self.generate_attributes()

    def generate_attributes(self) -> None:
        first = self._sanitize_timestamp(self._parameters.pop('first-seen', None))
        self._parameters['first-seen'] = first
        last = self._sanitize_timestamp(self._parameters.pop('last-seen', None))
        self._parameters['last-seen'] = last
        super().generate_attributes()
