from __future__ import annotations

import re
from collections.abc import Iterator
from io import BytesIO, StringIO

import pytest
import requests_mock

from pymisp import Distribution, MISPSharingGroup, PyMISP, __version__

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


def sent_path_and_named_params(http_mock: requests_mock.Mocker) -> tuple[str, dict[str, str]]:
    """Path of the last request without its named params, and the named params"""
    segments = http_mock.last_request.path.split('/')
    named = dict(segment.split(':', 1) for segment in segments if ':' in segment)
    return '/'.join(segment for segment in segments if ':' not in segment), named


@pytest.mark.parametrize('pseudofile', [StringIO(BUNDLE), BytesIO(BUNDLE.encode())])
def test_upload_stix_reads_full_pseudofile(misp: PyMISP, http_mock: requests_mock.Mocker,
                                           pseudofile: StringIO | BytesIO) -> None:
    pseudofile.seek(0, 2)

    misp.upload_stix(pseudofile)

    assert http_mock.last_request.body == BUNDLE.encode()


def test_upload_stix_sends_str_data_as_utf8(misp: PyMISP, http_mock: requests_mock.Mocker) -> None:
    misp.upload_stix(data=BUNDLE)

    assert http_mock.last_request.body == BUNDLE.encode()


def test_upload_stix_sends_misp_default_import_options(misp: PyMISP, http_mock: requests_mock.Mocker) -> None:
    misp.upload_stix(data=BUNDLE)

    assert sent_path_and_named_params(http_mock) == ('/events/upload_stix/2', {
        'publish': '0', 'original_file': '1', 'force_contextual_data': '1',
        'galaxies_as_tags': '0', 'debugging': '0'
    })
    assert http_mock.last_request.headers['Content-Type'] == 'application/json'


def test_upload_stix_sends_chosen_boolean_import_options(misp: PyMISP, http_mock: requests_mock.Mocker) -> None:
    misp.upload_stix(data=BUNDLE, publish=True, original_file=False, force_contextual_data=False,
                     galaxies_as_tags=True, debug=True)

    assert sent_path_and_named_params(http_mock)[1] == {
        'publish': '1', 'original_file': '0', 'force_contextual_data': '0',
        'galaxies_as_tags': '1', 'debugging': '1'
    }


def test_upload_stix_sends_distributions_and_sharing_group_ids(misp: PyMISP, http_mock: requests_mock.Mocker) -> None:
    sharing_group = MISPSharingGroup()
    sharing_group.from_dict(SharingGroup={'id': '7', 'name': 'Partners'})

    misp.upload_stix(data=BUNDLE, distribution=Distribution.sharing_group, sharing_group_id=sharing_group,
                     cluster_distribution=4, cluster_sharing_group_id=9)

    named = sent_path_and_named_params(http_mock)[1]
    assert {key: named.get(key) for key in ('distribution', 'sharing_group_id', 'cluster_distribution',
                                            'cluster_sharing_group_id')} == {
        'distribution': '4', 'sharing_group_id': '7', 'cluster_distribution': '4', 'cluster_sharing_group_id': '9'
    }


def test_upload_stix_1_keeps_raw_xml_body_with_import_options(misp: PyMISP, http_mock: requests_mock.Mocker) -> None:
    package = b'<stix:STIX_Package id="example:Package-1"/>'

    misp.upload_stix(data=package, version='1', distribution=1)

    path, named = sent_path_and_named_params(http_mock)
    assert (path, named['distribution']) == ('/events/upload_stix', '1')
    assert http_mock.last_request.headers['Content-Type'] == 'application/xml'
    assert http_mock.last_request.body == package
