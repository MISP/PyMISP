#!/usr/bin/env python

from __future__ import annotations

import logging

from typing import Any

from .abstractgenerator import AbstractMISPObjectGenerator

logger = logging.getLogger('pymisp')


class Fail2BanObject(AbstractMISPObjectGenerator):

    def __init__(self, parameters: dict[str, Any], strict: bool = True, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__('fail2ban', strict=strict, **kwargs)
        self._parameters = parameters
        self.generate_attributes()

    def generate_attributes(self) -> None:
        timestamp = self._sanitize_timestamp(self._parameters.pop('processing-timestamp', None))
        self._parameters['processing-timestamp'] = timestamp
        super().generate_attributes()
