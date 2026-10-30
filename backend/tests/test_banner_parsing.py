import unittest

from app.banner_parsing import parse_banner, service_family_for_module


class ServiceFamilyTests(unittest.TestCase):
    def test_extracts_family_from_scanner_module_path(self):
        self.assertEqual(service_family_for_module("scanner/ftp/ftp_version"), "ftp")
        self.assertEqual(service_family_for_module("scanner/http/http_version"), "http")

    def test_returns_none_for_non_scanner_paths(self):
        self.assertIsNone(service_family_for_module("exploit/windows/smb/ms17_010_eternalblue"))
        self.assertIsNone(service_family_for_module("not-a-path"))


class ParseBannerTests(unittest.TestCase):
    def test_ssh_openssh_banner(self):
        result = parse_banner("scanner/ssh/ssh_version", "SSH-2.0-OpenSSH_7.4")
        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "7.4")

    def test_ssh_openssh_banner_with_suffix(self):
        result = parse_banner("scanner/ssh/ssh_version", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "9.6p1")

    def test_ftp_vsftpd_banner(self):
        result = parse_banner("scanner/ftp/ftp_version", "220 (vsFTPd 3.0.3)")
        self.assertEqual(result.product, "vsftpd")
        self.assertEqual(result.version, "3.0.3")

    def test_ftp_proftpd_banner(self):
        result = parse_banner("scanner/ftp/ftp_version", "220 ProFTPD 1.3.5e Server ready.")
        self.assertEqual(result.product, "ProFTPD")
        self.assertEqual(result.version, "1.3.5e")

    def test_http_apache_banner(self):
        result = parse_banner("scanner/http/http_version", "Apache/2.4.49 (Unix)")
        self.assertEqual(result.product, "Apache httpd")
        self.assertEqual(result.version, "2.4.49")

    def test_http_nginx_banner(self):
        result = parse_banner("scanner/http/http_version", "nginx/1.18.0 (Ubuntu)")
        self.assertEqual(result.product, "nginx")
        self.assertEqual(result.version, "1.18.0")

    def test_smb_samba_banner(self):
        result = parse_banner("scanner/smb/smb_version", "Samba 4.7.6-Ubuntu")
        self.assertEqual(result.product, "Samba")
        self.assertEqual(result.version, "4.7.6-Ubuntu")

    def test_mysql_version_banner(self):
        result = parse_banner("scanner/mysql/mysql_version", "5.7.33-0ubuntu0.18.04.1")
        self.assertEqual(result.product, "MySQL")
        self.assertEqual(result.version, "5.7.33")

    def test_postgres_version_banner(self):
        result = parse_banner("scanner/postgres/postgres_version", "PostgreSQL 12.9 on x86_64-pc-linux-gnu")
        self.assertEqual(result.product, "PostgreSQL")
        self.assertEqual(result.version, "12.9")

    def test_redis_version_banner(self):
        result = parse_banner("scanner/redis/redis_server", "redis_version:6.0.9\r\nredis_mode:standalone")
        self.assertEqual(result.product, "Redis")
        self.assertEqual(result.version, "6.0.9")

    def test_unrecognized_family_returns_none(self):
        self.assertIsNone(parse_banner("scanner/snmp/snmp_enum", "anything"))

    def test_non_scanner_module_path_returns_none(self):
        self.assertIsNone(parse_banner("exploit/windows/smb/ms17_010_eternalblue", "anything"))

    def test_empty_info_returns_none(self):
        self.assertIsNone(parse_banner("scanner/ftp/ftp_version", ""))
        self.assertIsNone(parse_banner("scanner/ftp/ftp_version", "   "))

    def test_unmatched_banner_text_returns_none(self):
        # Recognized family, but text that doesn't match any known pattern -
        # should fail closed rather than guess.
        self.assertIsNone(parse_banner("scanner/ftp/ftp_version", "220 some-custom-ftpd ready"))


if __name__ == "__main__":
    unittest.main()
