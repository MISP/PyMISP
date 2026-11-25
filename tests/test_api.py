from __future__ import annotations

import re
from collections.abc import Iterator
from io import BytesIO, StringIO

import pytest
import requests_mock

from pymisp import PyMISP, __version__

URL = 'https://misp.test/'
BUNDLE = '{"type": "bundle", "id": "bundle--0c6dcb4a-1b04-4c3d-9e2b-9d8f4a7a7f10", "name": "Été"}'


@pytest.fixture
def http_mock() -> Iterator[requests_mock.Mocker]:
    """HTTP mock answering the calls of the PyMISP constructor and the STIX uploads"""
    with requests_mock.Mocker() as mock:
        mock.get(f'{URL}servers/getVersion',
                 json={'version': '3.0.0', 'pymisp_recommended_version': __version__})
        mock.get(f'{URL}users/view/me',
                 json={'User': {'id': '1'}, 'Role': {'id': '1'}, 'UserSetting': {}})
        mock.post(re.compile(r'/events/upload_stix'), json={'Event': {'id': '1'}})
        yield mock


@pytest.fixture
def misp(http_mock: requests_mock.Mocker) -> PyMISP:
    return PyMISP(URL, 'key')




@pytest.mark.parametrize('pseudofile', [StringIO(BUNDLE), BytesIO(BUNDLE.encode())])
def test_upload_stix_reads_full_pseudofile(misp: PyMISP, http_mock: requests_mock.Mocker,
                                           pseudofile: StringIO | BytesIO) -> None:
    pseudofile.seek(0, 2)

    misp.upload_stix(pseudofile)

    assert http_mock.last_request.body == BUNDLE.encode()


def test_upload_stix_sends_str_data_as_utf8(misp: PyMISP, http_mock: requests_mock.Mocker) -> None:
    misp.upload_stix(data=BUNDLE)

    assert http_mock.last_request.body == BUNDLE.encode()

