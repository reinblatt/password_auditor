#!/usr/bin/env python3
"""
Unit tests for the password auditor.
"""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from password_auditor import (
    Config,
    PasswordAuditor,
    PasswordResult,
    PasswordStrength,
    get_strength_color,
    read_passwords,
    validate_file
)

class MockResponse:
    """Mock response class for testing."""
    def __init__(self, status=200, text=""):
        self.status = status
        self._text = text

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None

class MockRequest:
    """Mock request context manager."""
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None

class TestPasswordStrength(unittest.TestCase):
    """Test password strength checking functionality."""

    def setUp(self):
        """Set up test environment."""
        self.auditor = PasswordAuditor(Config(input_file=Path("test.txt")))

    def test_password_strength(self):
        """Test password strength evaluation."""
        test_cases = [
            ("password", PasswordStrength.WEAK),      # Length 8, only lowercase
            ("Password1", PasswordStrength.STRONG),   # Length 9, has uppercase and number
            ("Password123!", PasswordStrength.VERY_STRONG),  # Length 12, has all types
            ("P@ssw0rd123!Long", PasswordStrength.VERY_STRONG),  # Long, has all types
            ("12345678", PasswordStrength.WEAK),      # Only numbers
            ("ABCDEFGH", PasswordStrength.WEAK),      # Only uppercase
            ("abcdefgh", PasswordStrength.WEAK),      # Only lowercase
            ("!@#$%^&*", PasswordStrength.WEAK),      # Only special chars
        ]

        for password, expected_strength in test_cases:
            with self.subTest(password=password):
                strength = self.auditor.check_password_strength(password)
                self.assertEqual(strength, expected_strength)

class TestPasswordAuditor(unittest.TestCase):
    """Test the PasswordAuditor class."""

    def setUp(self):
        """Set up test environment."""
        self.config = Config(
            input_file=Path("test_passwords.txt"),
            batch_size=5,
            timeout=5,
            rate_limit=0.1,
            verbose=False
        )
        self.auditor = PasswordAuditor(self.config)

    def test_hash_password(self):
        """Test password hashing."""
        test_cases = [
            ("password", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            ("", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"),
        ]

        for password, expected_hash in test_cases:
            with self.subTest(password=password):
                prefix, suffix = self.auditor.hash_password(password)
                self.assertEqual(prefix + suffix, expected_hash)

    def test_get_leak_count(self):
        """Test leak count extraction from API response."""
        test_cases = [
            (
                "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
                "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n",
                "0018A45C4D1DEF81644B54AB7F969B88D65",
                1
            ),
            (
                "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
                "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                0
            ),
        ]

        for response_text, hash_suffix, expected_count in test_cases:
            with self.subTest(hash_suffix=hash_suffix):
                count = self.auditor._get_leak_count(response_text, hash_suffix)
                self.assertEqual(count, expected_count)

    @patch('aiohttp.ClientSession')
    def test_check_password(self, mock_session):
        """Test password checking with mock API response."""
        # Create mock response with the correct hash prefix for "password123"
        # SHA1 of "password123" is CBFDAC6008F9CAB4083784CBD1874F76618D2A97
        # Prefix is CBFDA, suffix is C6008F9CAB4083784CBD1874F76618D2A97
        mock_response = MockResponse(
            status=200,
            text="C6008F9CAB4083784CBD1874F76618D2A97:1\n"
        )

        # Create mock request
        mock_request = MockRequest(mock_response)

        # Setup session mock
        mock_session_instance = MagicMock()
        mock_session_instance.get.return_value = mock_request
        mock_session.return_value.__aenter__.return_value = mock_session_instance

        # Test password checking
        result = asyncio.run(self.auditor.check_password(mock_session_instance, "password123"))
        
        # Debug: Print the actual hash values
        prefix, suffix = self.auditor.hash_password("password123")
        print(f"Generated prefix: {prefix}")
        print(f"Generated suffix: {suffix}")
        print(f"Expected suffix: C6008F9CAB4083784CBD1874F76618D2A97")
        
        self.assertIsInstance(result, PasswordResult)
        self.assertEqual(result.password, "password123")
        self.assertEqual(result.leak_count, 1)
        self.assertIsInstance(result.strength, PasswordStrength)
        self.assertIsNone(result.error)

    @patch('aiohttp.ClientSession')
    def test_check_password_error(self, mock_session):
        """Test password checking with API error."""
        # Create mock response
        mock_response = MockResponse(
            status=500,
            text=""
        )

        # Create mock request
        mock_request = MockRequest(mock_response)

        # Setup session mock
        mock_session_instance = MagicMock()
        mock_session_instance.get.return_value = mock_request
        mock_session.return_value.__aenter__.return_value = mock_session_instance

        # Test password checking with error
        result = asyncio.run(self.auditor.check_password(mock_session_instance, "password123"))
        
        self.assertIsInstance(result, PasswordResult)
        self.assertEqual(result.password, "password123")
        self.assertEqual(result.leak_count, -1)
        self.assertIsNotNone(result.error)

    def test_cache_operations(self):
        """Test cache loading and saving."""
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            # Create test cache
            test_cache = {
                "password1": 1,
                "password2": 0
            }
            json.dump(test_cache, temp_file)
            temp_file.flush()

            # Test cache loading
            self.auditor.config.cache_file = Path(temp_file.name)
            self.auditor.cache = self.auditor._load_cache()
            self.assertEqual(self.auditor.cache, test_cache)

            # Test cache saving
            self.auditor.cache["password3"] = 2
            self.auditor._save_cache()

            # Verify saved cache
            with open(temp_file.name, 'r') as f:
                saved_cache = json.load(f)
                self.assertEqual(saved_cache["password3"], 2)

        # Cleanup
        os.unlink(temp_file.name)

class TestFileOperations(unittest.TestCase):
    """Test file operations."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = Path(self.temp_dir) / "test_passwords.txt"

    def tearDown(self):
        """Clean up test environment."""
        if self.test_file.exists():
            self.test_file.unlink()
        os.rmdir(self.temp_dir)

    def test_validate_file(self):
        """Test file validation."""
        # Create a test file
        with open(self.test_file, 'w') as f:
            f.write("test\n")

        # Test valid file
        result = validate_file(str(self.test_file))
        self.assertEqual(result, self.test_file)

        # Test non-existent file
        result = validate_file(str(self.test_file) + ".nonexistent")
        self.assertIsNone(result)

    def test_read_passwords(self):
        """Test password file reading."""
        # Create test file with passwords
        test_passwords = ["password1", "password2", "password3"]
        with open(self.test_file, 'w') as f:
            f.write("\n".join(test_passwords))

        # Test reading passwords
        passwords = read_passwords(self.test_file)
        self.assertEqual(passwords, test_passwords)

        # Test reading empty file
        with open(self.test_file, 'w') as f:
            f.write("")
        passwords = read_passwords(self.test_file)
        self.assertEqual(passwords, [])

class TestColorOutput(unittest.TestCase):
    """Test color output functionality."""

    def test_strength_colors(self):
        """Test color assignment for password strengths."""
        test_cases = [
            (PasswordStrength.VERY_WEAK, "\x1b[31m"),
            (PasswordStrength.WEAK, "\x1b[33m"),
            (PasswordStrength.MEDIUM, "\x1b[34m"),
            (PasswordStrength.STRONG, "\x1b[32m"),
            (PasswordStrength.VERY_STRONG, "\x1b[36m"),
        ]

        for strength, expected_color in test_cases:
            with self.subTest(strength=strength):
                color = get_strength_color(strength)
                self.assertEqual(color, expected_color)

if __name__ == '__main__':
    unittest.main() 