from io import BytesIO, StringIO
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
