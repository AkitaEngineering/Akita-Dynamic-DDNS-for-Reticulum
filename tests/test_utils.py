# tests/test_utils.py
import os
import unittest

import pytest

from akita_ddns.utils import RateLimiter, load_or_create_identity, parse_name


class TestUtils(unittest.TestCase):
    def test_parse_name_simple(self):
        name, ns = parse_name("test", "default")
        self.assertEqual(name, "test")
        self.assertEqual(ns, "default")

    def test_parse_name_with_namespace(self):
        name, ns = parse_name("test.home", "default")
        self.assertEqual(name, "test")
        self.assertEqual(ns, "home")

    def test_parse_name_empty(self):
        with self.assertRaises(ValueError):
            parse_name("", "default")

    def test_parse_name_invalid(self):
        with self.assertRaises(ValueError):
            parse_name(".", "default")

    def test_parse_name_rejects_explicit_empty_namespace(self):
        with self.assertRaises(ValueError):
            parse_name("test.", "default")

    def test_rate_limiter(self):
        rl = RateLimiter(2.0)  # 2 requests per second
        self.assertTrue(rl.check())
        self.assertTrue(rl.check())
        self.assertFalse(rl.check())  # Should be rate limited


if __name__ == "__main__":
    unittest.main()


def test_identity_creation_is_private_and_invalid_file_is_not_replaced(tmp_path):
    identity_path = tmp_path / "identity"
    created = load_or_create_identity(str(identity_path))

    assert created.hash
    assert os.stat(identity_path).st_mode & 0o777 == 0o600

    identity_path.write_bytes(b"invalid")
    with pytest.raises(ValueError, match="invalid"):
        load_or_create_identity(str(identity_path))
    assert identity_path.read_bytes() == b"invalid"
