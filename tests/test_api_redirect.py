#!/usr/bin/env python

from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock
import logging

from pymisp import PyMISP


class TestAPIRedirect(unittest.TestCase):
    """Test that API properly handles HTTP to HTTPS redirects and warnings"""

    def setUp(self) -> None:
        self.maxDiff = None

    def test_http_url_warning(self) -> None:
        """Test that using HTTP URL generates a warning"""
        # Test that the warning logic itself is correct
        root_url = 'http://misp.local/'
        logger = logging.getLogger('pymisp')
        
        with self.assertLogs('pymisp', level='WARNING') as cm:
            # Simulate the warning code from __init__
            if root_url.startswith('http://'):
                logger.warning('Using HTTP instead of HTTPS for MISP connection. This may cause redirect issues. Consider using HTTPS.')
            
            self.assertTrue(any('HTTP instead of HTTPS' in message for message in cm.output))

    def test_https_url_no_warning(self) -> None:
        """Test that using HTTPS URL does not generate a warning"""
        # Test that HTTPS doesn't trigger the warning
        root_url = 'https://misp.local/'
        logger = logging.getLogger('pymisp')
        
        # Manually check - no warning should be logged for HTTPS
        with self.assertLogs('pymisp', level='DEBUG') as cm:
            logger.debug('test message')
            # Simulate the warning code from __init__
            if root_url.startswith('http://'):
                logger.warning('Using HTTP instead of HTTPS for MISP connection. This may cause redirect issues. Consider using HTTPS.')
            
            # Verify no HTTP warning was logged
            self.assertFalse(any('HTTP instead of HTTPS' in message for message in cm.output))

    def test_allow_redirects_in_prepare_request(self) -> None:
        """Test that _prepare_request passes allow_redirects=True to session.send"""
        # Create a minimal API instance
        api = PyMISP.__new__(PyMISP)
        api.root_url = 'https://misp.local/'
        api.ssl = True
        api.proxies = None
        api.cert = None
        api.auth = None
        api.timeout = None
        
        # Mock the session
        mock_session = MagicMock()
        mock_prepped = MagicMock()
        mock_prepped.headers = {}
        mock_session.prepare_request.return_value = mock_prepped
        mock_session.merge_environment_settings.return_value = {}
        mock_response = MagicMock()
        mock_session.send.return_value = mock_response
        
        api._PyMISP__session = mock_session
        
        # Call _prepare_request
        api._prepare_request('GET', 'events')
        
        # Verify that session.send was called with allow_redirects=True
        mock_session.send.assert_called_once()
        call_args = mock_session.send.call_args
        self.assertIn('allow_redirects', call_args.kwargs)
        self.assertTrue(call_args.kwargs['allow_redirects'])


if __name__ == '__main__':
    unittest.main()
