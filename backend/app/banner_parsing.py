"""
Parses the confirmed `info` string Metasploit's scanner/*/x_version modules
write via report_service (see versionDetection.ts on the frontend) into a
structured {product, version} pair.

This exists to feed the "suggested next steps" matcher (ROADMAP.md, Phase
2): once a service is *confirmed* (not just guessed from a port number), we
want to turn its banner into something that can be matched against exploit
module metadata (names/descriptions/refs), rather than re-guessing from the
port.

Each scanner module formats `info` differently - there is no shared schema
across ftp_version, ssh_version, http_version, etc. - so this is
deliberately a set of small, independent per-service parsers rather than
one generic regex. A parser that can't confidently extract both a product
and a version returns None; callers should treat that as "confirmed open,
but not enough to suggest from" rather than guessing.

Nothing here identifies a vulnerability by itself - it only normalizes what
Metasploit already reported, for the next step to match against module
metadata.
"""
from __future__ import annotations

import re
from typing import NamedTuple


class ParsedBanner(NamedTuple):
    product: str
    version: str
    # The exact substring of `info` that version came from, so a caller
    # that wants to show its work (or double check) still can.
    raw: str


def _match(pattern: str, info: str, flags: int = re.IGNORECASE) -> re.Match | None:
    return re.search(pattern, info, flags)


def _parse_ssh(info: str) -> ParsedBanner | None:
    # e.g. "SSH-2.0-OpenSSH_7.4", "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20", or "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    m = _match(r"(?:SSH-\d\.\d-)?(OpenSSH|dropbear|libssh)[_ ]([\d.]+\w*)", info)
    if m:
        return ParsedBanner(product=m.group(1), version=m.group(2), raw=m.group(0))
    m = _match(r"SSH-\d\.\d-([A-Za-z0-9_.-]+?)_([\w.]+)", info)
    if not m:
        return None
    return ParsedBanner(product=m.group(1), version=m.group(2), raw=m.group(0))


def _parse_ftp(info: str) -> ParsedBanner | None:
    # ftp_version's info is usually the raw 220 banner, e.g.
    # "220 ProFTPD 1.3.5e Server" or "220 (vsFTPd 3.0.3)"
    m = _match(r"vsftpd\)?\s*([\d.]+)", info) or _match(r"vsFTPd\s+([\d.]+)", info)
    if m:
        return ParsedBanner(product="vsftpd", version=m.group(1), raw=m.group(0))
    m = _match(r"ProFTPD\s+([\d.]+\w*)", info)
    if m:
        return ParsedBanner(product="ProFTPD", version=m.group(1), raw=m.group(0))
    m = _match(r"Pure-?FTPd\s*([\d.]*)", info)
    if m:
        return ParsedBanner(product="Pure-FTPd", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"Microsoft FTP Service", info)
    if m:
        return ParsedBanner(product="Microsoft FTP Service", version="unknown", raw=m.group(0))
    return None


def _parse_smtp(info: str) -> ParsedBanner | None:
    m = _match(r"Postfix", info)
    if m:
        return ParsedBanner(product="Postfix", version="unknown", raw=m.group(0))
    m = _match(r"Exim\s+([\d.]+)", info)
    if m:
        return ParsedBanner(product="Exim", version=m.group(1), raw=m.group(0))
    m = _match(r"Sendmail\s+([\d.]+)", info)
    if m:
        return ParsedBanner(product="Sendmail", version=m.group(1), raw=m.group(0))
    m = _match(r"Microsoft ESMTP MAIL Service", info)
    if m:
        return ParsedBanner(product="Microsoft Exchange/IIS SMTP", version="unknown", raw=m.group(0))
    return None


def _parse_http(info: str) -> ParsedBanner | None:
    # http_version's info is the raw Server header or response snippet, e.g.
    # "Apache/2.4.49 (Unix)" or "nginx/1.18.0 (Ubuntu)" or "Microsoft-IIS/10.0"
    m = _match(r"Apache(?:/([\d.]+))?", info)
    if m:
        return ParsedBanner(product="Apache httpd", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"nginx(?:/([\d.]+))?", info)
    if m:
        return ParsedBanner(product="nginx", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"Microsoft-IIS(?:/([\d.]+))?", info)
    if m:
        return ParsedBanner(product="Microsoft IIS", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"lighttpd(?:/([\d.]+))?", info)
    if m:
        return ParsedBanner(product="lighttpd", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"Tomcat(?:/([\d.]+))?", info) or _match(r"Apache-Coyote(?:/([\d.]+))?", info)
    if m:
        return ParsedBanner(product="Apache Tomcat", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"uvicorn", info)
    if m:
        return ParsedBanner(product="uvicorn", version="unknown", raw=m.group(0))
    m = _match(r"Werkzeug(?:/([\d.]+))?", info)
    if m:
        return ParsedBanner(product="Werkzeug", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"gunicorn(?:/([\d.]+))?", info)
    if m:
        return ParsedBanner(product="gunicorn", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"Node\.js|Express", info)
    if m:
        return ParsedBanner(product="Node.js Express", version="unknown", raw=m.group(0))
    return None


def _parse_smb(info: str) -> ParsedBanner | None:
    # smb_version's info typically includes an OS/product string, e.g.
    # "Windows Server 2019 Standard 17763" or "Samba 4.7.6-Ubuntu"
    m = _match(r"Samba\s+([\w.+-]+)", info)
    if m:
        return ParsedBanner(product="Samba", version=m.group(1), raw=m.group(0))
    m = _match(r"Windows\s+(Server\s+)?([\d]{4}|XP|Vista|7|8|10|11)\b", info)
    if m:
        version = f"{m.group(1) or ''}{m.group(2)}".strip()
        return ParsedBanner(product="Windows", version=version, raw=m.group(0))
    return None


def _parse_mysql(info: str) -> ParsedBanner | None:
    # mysql_version's info is usually the raw server version string, e.g.
    # "5.7.33-0ubuntu0.18.04.1" or "8.0.27"
    m = _match(r"MariaDB", info)
    if m:
        version_match = _match(r"([\d]+\.[\d.]+)", info)
        return ParsedBanner(product="MariaDB", version=version_match.group(1) if version_match else "unknown", raw=info[:80])
    m = _match(r"^\s*([\d]+\.[\d.]+)", info)
    if m:
        return ParsedBanner(product="MySQL", version=m.group(1), raw=m.group(0))
    return None


def _parse_postgres(info: str) -> ParsedBanner | None:
    m = _match(r"PostgreSQL\s+([\d.]+)", info)
    if m:
        return ParsedBanner(product="PostgreSQL", version=m.group(1), raw=m.group(0))
    return None


def _parse_redis(info: str) -> ParsedBanner | None:
    m = _match(r"redis_version:\s*([\d.]+)", info) or _match(r"Redis\s+(?:server\s+)?v?([\d.]+)", info)
    if m:
        return ParsedBanner(product="Redis", version=m.group(1), raw=m.group(0))
    return None


def _parse_telnet(info: str) -> ParsedBanner | None:
    # telnet_version mostly returns whatever banner text the service sent;
    # there's no consistent product/version structure to rely on here.
    return None


def _parse_rdp(info: str) -> ParsedBanner | None:
    m = _match(r"TLS\s*[:=]?\s*([\d.]+)", info)
    if m:
        return ParsedBanner(product="RDP (TLS)", version=m.group(1), raw=m.group(0))
    return None


def _parse_imap_pop3(info: str) -> ParsedBanner | None:
    m = _match(r"Dovecot(?:\s+([\w.]+))?", info)
    if m:
        return ParsedBanner(product="Dovecot", version=m.group(1) or "unknown", raw=m.group(0))
    m = _match(r"Courier", info)
    if m:
        return ParsedBanner(product="Courier", version="unknown", raw=m.group(0))
    return None


# Maps the RPORT-service family (as used by versionDetection.ts's module
# paths) to the parser that understands that module's info format.
_PARSERS_BY_MODULE_FAMILY: dict[str, "callable[[str], ParsedBanner | None]"] = {
    "ftp": _parse_ftp,
    "ssh": _parse_ssh,
    "telnet": _parse_telnet,
    "smtp": _parse_smtp,
    "pop3": _parse_imap_pop3,
    "imap": _parse_imap_pop3,
    "http": _parse_http,
    "smb": _parse_smb,
    "mysql": _parse_mysql,
    "rdp": _parse_rdp,
    "postgres": _parse_postgres,
    "redis": _parse_redis,
}


def service_family_for_module(module_path: str) -> str | None:
    """
    versionDetection.ts's module paths look like "scanner/ftp/ftp_version" -
    pull out the "ftp" segment so the right parser can be selected without
    duplicating the port->family mapping that already lives in the frontend.
    """
    parts = module_path.split("/")
    return parts[1] if len(parts) >= 2 and parts[0] == "scanner" else None


def parse_banner(module_path: str, info: str) -> ParsedBanner | None:
    """
    Parse a confirmed `info` string into {product, version}, selecting the
    parser by which scanner module produced it. Returns None if the family
    is unrecognized or the banner doesn't match a known format - callers
    should treat that as "can't suggest from this yet", not as an error.
    """
    if not info or not info.strip():
        return None
    family = service_family_for_module(module_path)
    if family is None:
        return None
    parser = _PARSERS_BY_MODULE_FAMILY.get(family)
    if parser is None:
        return None
    return parser(info)


_FAMILY_BY_PORT: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    465: "smtp",
    587: "smtp",
    80: "http",
    110: "pop3",
    139: "smb",
    143: "imap",
    443: "http",
    445: "smb",
    3000: "http",
    3306: "mysql",
    3389: "rdp",
    5000: "http",
    5432: "postgres",
    6379: "redis",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8443: "http",
    8888: "http",
    9000: "http",
    9200: "http",
}


def parse_service_banner(info: str, port: int | None = None) -> ParsedBanner | None:
    """
    Parse a service banner string into a structured ParsedBanner.
    If a port is provided, tries the parser for that port's service family first.
    If that fails or port is not given, tries the other registered parsers.
    """
    if not info or not info.strip():
        return None

    if port is not None and port in _FAMILY_BY_PORT:
        family = _FAMILY_BY_PORT[port]
        parser = _PARSERS_BY_MODULE_FAMILY.get(family)
        if parser:
            parsed = parser(info)
            if parsed is not None:
                return parsed

    for parser in _PARSERS_BY_MODULE_FAMILY.values():
        parsed = parser(info)
        if parsed is not None:
            return parsed

    return None

