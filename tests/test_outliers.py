"""Keep RP-specific workarounds narrowly scoped."""

import unittest

from src.outliers import should_store_discoverable


class OutlierTest(unittest.TestCase):
    def test_only_discord_overrides_false_rk(self):
        self.assertTrue(should_store_discoverable("discord.com", False))
        self.assertFalse(should_store_discoverable("login.discord.com", False))
        self.assertFalse(should_store_discoverable("example.com", False))
        self.assertTrue(should_store_discoverable("example.com", True))


if __name__ == "__main__":
    unittest.main()
