#!/usr/bin/env python

from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock, Mock
import requests

from pymisp.api import PyMISP


class TestAPIRedirects(unittest.TestCase):
    """Test cases for HTTP to HTTPS redirect handling in PyMISP API calls"""

    def setUp(self) -> None:
        """Set up test fixtures"""
        self.maxDiff = None

    @patch.object(PyMISP, '__init__', lambda x, y, z, **kwargs: None)
    def test_prepare_request_includes_allow_redirects(self):
        """Test that _prepare_request passes allow_redirects=True to session.send"""
        # Create a PyMISP instance with mocked __init__
        pymisp = PyMISP(None, None)
        
        # Manually set required attributes that would normally be set in __init__
        pymisp.root_url = 'http://misp.local'
        pymisp.timeout = 30
        pymisp.auth = None
        pymisp.proxies = None
        pymisp.ssl = False
        pymisp.cert = None
        pymisp._PyMISP__session = MagicMock(spec=requests.Session)
        
        # Mock the session.send method to capture how it's called
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {'test': 'data'}
        pymisp._PyMISP__session.send.return_value = mock_response
        pymisp._PyMISP__session.prepare_request = Mock(return_value=Mock())
        pymisp._PyMISP__session.merge_environment_settings = Mock(return_value={})
        
        # Make a GET request through _prepare_request
        pymisp._prepare_request('GET', 'events/index')
        
        # Verify session.send was called with allow_redirects=True
        pymisp._PyMISP__session.send.assert_called_once()
        call_kwargs = pymisp._PyMISP__session.send.call_args.kwargs
        self.assertIn('allow_redirects', call_kwargs,
                     "allow_redirects parameter should be passed to session.send")
        self.assertTrue(call_kwargs['allow_redirects'],
                       "allow_redirects should be True")

    @patch.object(PyMISP, '__init__', lambda x, y, z, **kwargs: None)
    def test_prepare_request_post_includes_allow_redirects(self):
        """Test that POST requests also include allow_redirects=True"""
        # Create a PyMISP instance with mocked __init__
        pymisp = PyMISP(None, None)
        
        # Manually set required attributes
        pymisp.root_url = 'http://misp.local'
        pymisp.timeout = 30
        pymisp.auth = None
        pymisp.proxies = None
        pymisp.ssl = False
        pymisp.cert = None
        pymisp._PyMISP__session = MagicMock(spec=requests.Session)
        
        # Mock the session methods
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {'Event': {'id': '1'}}
        pymisp._PyMISP__session.send.return_value = mock_response
        pymisp._PyMISP__session.prepare_request = Mock(return_value=Mock())
        pymisp._PyMISP__session.merge_environment_settings = Mock(return_value={})
        
        # Make a POST request through _prepare_request
        pymisp._prepare_request('POST', 'events/add', data={'info': 'Test Event'})
        
        # Verify session.send was called with allow_redirects=True
        pymisp._PyMISP__session.send.assert_called_once()
        call_kwargs = pymisp._PyMISP__session.send.call_args.kwargs
        self.assertIn('allow_redirects', call_kwargs,
                     "allow_redirects parameter should be passed to session.send for POST requests")
        self.assertTrue(call_kwargs['allow_redirects'],
                       "allow_redirects should be True for POST requests")

    @patch.object(PyMISP, '__init__', lambda x, y, z, **kwargs: None)
    def test_prepare_request_all_methods_allow_redirects(self):
        """Test that all HTTP methods include allow_redirects=True"""
        # Create a PyMISP instance with mocked __init__
        pymisp = PyMISP(None, None)
        
        # Manually set required attributes
        pymisp.root_url = 'http://misp.local'
        pymisp.timeout = 30
        pymisp.auth = None
        pymisp.proxies = None
        pymisp.ssl = False
        pymisp.cert = None
        pymisp._PyMISP__session = MagicMock(spec=requests.Session)
        
        # Mock the session methods
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': 'success'}
        pymisp._PyMISP__session.send.return_value = mock_response
        pymisp._PyMISP__session.prepare_request = Mock(return_value=Mock())
        pymisp._PyMISP__session.merge_environment_settings = Mock(return_value={})
        
        # Test various HTTP methods
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            pymisp._PyMISP__session.send.reset_mock()
            
            # Make a request with this method
            pymisp._prepare_request(method, 'test/endpoint', data={'test': 'data'} if method in ['POST', 'PUT', 'PATCH'] else None)
            
            # Verify session.send was called with allow_redirects=True
            pymisp._PyMISP__session.send.assert_called_once()
            call_kwargs = pymisp._PyMISP__session.send.call_args.kwargs
            self.assertIn('allow_redirects', call_kwargs,
                         f"allow_redirects parameter should be passed for {method} requests")
            self.assertTrue(call_kwargs['allow_redirects'],
                           f"allow_redirects should be True for {method} requests")


if __name__ == '__main__':
    unittest.main()
