# tests/test_utils.py
import unittest
from akita_ddns.utils import parse_name, RateLimiter
import time

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

    def test_rate_limiter(self):
        rl = RateLimiter(2.0)  # 2 requests per second
        self.assertTrue(rl.check())
        self.assertTrue(rl.check())
        self.assertFalse(rl.check())  # Should be rate limited

if __name__ == "__main__":
    unittest.main()