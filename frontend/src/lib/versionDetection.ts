/**
 * Maps a well-known port to the actual Metasploit scanner module that
 * fingerprints the real service running there, as opposed to the
 * port-number guess in portSuggestions.ts. Each of these modules connects
 * to the service and calls report_service with the banner/version it
 * found, so after running one, re-reading db.services for that host:port
 * returns a confirmed `info` string instead of nothing.
 *
 * This list is deliberately conservative: it only includes modules intended
 * to fingerprint a service over the discovered TCP port. It excludes modules
 * that test credentials or authentication posture (for example SNMP login
 * and VNC no-auth checks), and MSSQL browser discovery (UDP 1434 rather than
 * the discovered TCP 1433 service). Those checks must be selected explicitly
 * as security tests, not presented as passive version detection.
 */
export type VersionDetectionModule = {
  /** Module path under auxiliary/, as accepted by api.modules.execute("auxiliary", ...). */
  module: string;
  /** Extra datastore options beyond RHOSTS/RPORT, e.g. SSL for HTTPS ports. */
  options?: Record<string, string>;
};

const VERSION_DETECTION_MODULES: Record<number, VersionDetectionModule> = {
  21: { module: "scanner/ftp/ftp_version" },
  22: { module: "scanner/ssh/ssh_version" },
  23: { module: "scanner/telnet/telnet_version" },
  25: { module: "scanner/smtp/smtp_version" },
  53: { module: "scanner/dns/dns_version" },
  80: { module: "scanner/http/http_version" },
  110: { module: "scanner/pop3/pop3_version" },
  139: { module: "scanner/smb/smb_version" },
  143: { module: "scanner/imap/imap_version" },
  443: { module: "scanner/http/http_version", options: { SSL: "true" } },
  445: { module: "scanner/smb/smb_version" },
  3000: { module: "scanner/http/http_version" },
  3306: { module: "scanner/mysql/mysql_version" },
  3389: { module: "scanner/rdp/rdp_scanner" },
  5000: { module: "scanner/http/http_version" },
  5432: { module: "scanner/postgres/postgres_version" },
  6379: { module: "scanner/redis/redis_server" },
  8000: { module: "scanner/http/http_version" },
  8008: { module: "scanner/http/http_version" },
  8080: { module: "scanner/http/http_version" },
  8081: { module: "scanner/http/http_version" },
  8443: { module: "scanner/http/http_version", options: { SSL: "true" } },
  8888: { module: "scanner/http/http_version" },
  9000: { module: "scanner/http/http_version" },
  9200: { module: "scanner/http/http_version" },
  9443: { module: "scanner/http/http_version", options: { SSL: "true" } },
};

export function detectionModuleForPort(port: number): VersionDetectionModule | null {
  return VERSION_DETECTION_MODULES[port] ?? null;
}
