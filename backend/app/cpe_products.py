"""
Explicit product -> NVD CPE identity table used by NvdClient.assess_product_version.

Keys are the product name as produced by app.banner_parsing, lowercased with
every non-alphanumeric character removed ("Apache httpd" -> "apachehttpd").
Values are the (vendor, product) pairs NVD uses in CPE 2.3 criteria strings
(cpe:2.3:<part>:<vendor>:<product>:...). Some software appears under several
vendors across NVD's history (company renames, project moves), so a key can
list more than one pair.

Unknown products deliberately stay "indeterminate" rather than being matched
by loose substring heuristics, so a wrong or missing entry can only make a
result less certain, never produce a false match. Check a new entry against
NVD's CPE dictionary before adding it.
"""
from __future__ import annotations

CPE_PRODUCT_IDENTITIES: dict[str, set[tuple[str, str]]] = {
    # SSH servers and libraries
    "openssh": {("openbsd", "openssh"), ("openssh", "openssh")},
    "dropbear": {
        ("dropbear", "dropbear"),
        ("dropbear_ssh_project", "dropbear_ssh"),
        ("matt_johnston", "dropbear_ssh_server"),
    },
    "libssh": {("libssh", "libssh")},
    # FTP
    "vsftpd": {("vsftpd", "vsftpd")},
    "proftpd": {("proftpd", "proftpd")},
    "pureftpd": {("pureftpd", "pure-ftpd")},
    # Mail
    "exim": {("exim", "exim")},
    "sendmail": {("sendmail", "sendmail")},
    "dovecot": {("dovecot", "dovecot")},
    # Web servers and app servers
    "apachehttpd": {("apache", "http_server")},
    "apachehttpserver": {("apache", "http_server")},
    "nginx": {("nginx", "nginx"), ("f5", "nginx")},
    "apachetomcat": {("apache", "tomcat")},
    "tomcat": {("apache", "tomcat")},
    "lighttpd": {("lighttpd", "lighttpd")},
    "microsoftiis": {
        ("microsoft", "internet_information_server"),
        ("microsoft", "internet_information_services"),
    },
    "werkzeug": {("palletsprojects", "werkzeug"), ("pocoo", "werkzeug")},
    "gunicorn": {("gunicorn", "gunicorn"), ("benoitc", "gunicorn")},
    # File sharing
    "samba": {("samba", "samba")},
    # Databases
    "mysql": {("oracle", "mysql"), ("mysql", "mysql")},
    "mariadb": {("mariadb", "mariadb")},
    "postgresql": {("postgresql", "postgresql")},
    "postgres": {("postgresql", "postgresql")},
    "redis": {("redis", "redis")},
}
