import re
import unittest

from app.banner_parsing import parse_service_banner
from app.cpe_products import CPE_PRODUCT_IDENTITIES

# One real-looking banner per product that app.banner_parsing can report with a
# version, so a renamed or missing table entry shows up as a failing test.
VERSIONED_BANNERS = [
    ("SSH-2.0-OpenSSH_7.4", 22),
    ("SSH-2.0-dropbear_2019.78", 22),
    ("SSH-2.0-libssh_0.8.1", 22),
    ("220 (vsFTPd 3.0.3)", 21),
    ("220 ProFTPD 1.3.5e Server", 21),
    ("220 Pure-FTPd 1.0.49", 21),
    ("220 mail.example.com ESMTP Exim 4.94.2", 25),
    ("220 host.example.com ESMTP Sendmail 8.15.2", 25),
    ("* OK Dovecot ready.", 143),
    ("Apache/2.4.49 (Unix)", 80),
    ("Apache-Coyote/1.1", 8080),
    ("nginx/1.18.0", 80),
    ("Microsoft-IIS/7.5", 80),
    ("lighttpd/1.4.55", 80),
    ("Werkzeug/2.0.1 Python/3.9.7", 5000),
    ("gunicorn/20.1.0", 8000),
    ("Samba 4.7.6-Ubuntu", 445),
    ("5.7.33-0ubuntu0.18.04.1", 3306),
    ("5.5.5-10.3.27-MariaDB", 3306),
    ("PostgreSQL 13.3 on x86_64-pc-linux-gnu", 5432),
    ("redis_version:6.0.9", 6379),
]


def normalize(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


class CpeProductTableTests(unittest.TestCase):
    def test_keys_are_normalized_product_names(self):
        for key in CPE_PRODUCT_IDENTITIES:
            self.assertEqual(key, normalize(key), key)

    def test_identities_are_lowercase_vendor_product_pairs(self):
        for key, identities in CPE_PRODUCT_IDENTITIES.items():
            self.assertTrue(identities, key)
            for vendor, product in identities:
                for part in (vendor, product):
                    self.assertTrue(part, key)
                    self.assertEqual(part, part.lower(), key)
                    self.assertNotRegex(part, r"[\s:*]", key)


class DropbearCpeIdentityTests(unittest.TestCase):
    def test_uses_current_and_historical_nvd_dropbear_identities(self):
        identities = CPE_PRODUCT_IDENTITIES["dropbear"]
        self.assertIn(("dropbear_ssh_project", "dropbear_ssh"), identities)
        self.assertIn(("dropbear_project", "dropbear"), identities)
        self.assertIn(("matt_johnston", "dropbear_ssh_server"), identities)
        self.assertNotIn(("dropbear", "dropbear"), identities)


class BannerProductsAreMappedTests(unittest.TestCase):
    def test_every_versioned_banner_product_has_a_cpe_mapping(self):
        for banner, port in VERSIONED_BANNERS:
            with self.subTest(banner=banner):
                parsed = parse_service_banner(banner, port)
                self.assertIsNotNone(parsed)
                self.assertIn(normalize(parsed.product), CPE_PRODUCT_IDENTITIES)


if __name__ == "__main__":
    unittest.main()
