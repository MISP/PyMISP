from io import BytesIO, StringIO
from typing import Any
from unittest.mock import patch

import pytest

from pymisp import PyMISP


@pytest.mark.parametrize('pseudofile', [StringIO('{"type": "bundle"}'), BytesIO(b'{"type": "bundle"}')])
def test_upload_stix_reads_full_pseudofile(pseudofile: StringIO | BytesIO) -> None:
    misp = PyMISP.__new__(PyMISP)
    misp.root_url = 'https://example.test/'
    pseudofile.seek(0, 2)

    with patch.object(misp, '_prepare_request') as prepare_request:
        misp.upload_stix(pseudofile)

    prepare_request.assert_called_once_with(
        'POST', 'https://example.test/events/upload_stix/2', data=pseudofile.getvalue()
    )


@pytest.mark.parametrize(
    ('method_name', 'args', 'expected_url'),
    [
        ('fetch_all_feeds', (), 'feeds/fetchFromAllFeeds'),
        ('fetch_feed', (1,), 'feeds/fetchFromFeed/1'),
        ('cache_all_feeds', (), 'feeds/cacheFeeds/all'),
        ('cache_feed', (1,), 'feeds/cacheFeeds/1'),
        ('cache_freetext_feeds', (), 'feeds/cacheFeeds/freetext'),
        ('cache_misp_feeds', (), 'feeds/cacheFeeds/misp'),
        ('load_default_feeds', (), 'feeds/loadDefaultFeeds'),
    ],
)
def test_feed_trigger_endpoints_use_post(method_name: str, args: tuple[Any, ...], expected_url: str) -> None:
    misp = PyMISP.__new__(PyMISP)
    misp.root_url = 'https://example.test/'

    with (
        patch.object(misp, '_prepare_request') as prepare_request,
        patch.object(misp, '_check_json_response', return_value={'result': 'ok'}) as check_json_response,
    ):
        result = getattr(misp, method_name)(*args)

    prepare_request.assert_called_once_with('POST', expected_url)
    check_json_response.assert_called_once_with(prepare_request.return_value)
    assert result == {'result': 'ok'}
