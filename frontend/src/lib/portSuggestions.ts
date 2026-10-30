/**
 * Plain-language guesses for what a service on a well-known port probably
 * is, used only to point someone at a sensible next search in the module
 * browser after a port scan. This is a GUESS based on the port number
 * alone (the TCP port scanner Metasploit runs here only confirms a port is
 * open, not what's actually listening on it) - it is deliberately labeled
 * as such everywhere it's shown, and the module browser's own search is
 * always the next step, not a specific exploit claim. Never treat this as
 * identifying a real vulnerability or a confirmed service.
 */
export type PortSuggestion = {
  label: string;
  keyword: string;
  note: string;
  defaultType?: "exploit" | "auxiliary";
};

const PORT_SUGGESTIONS: Record<number, PortSuggestion> = {
  21: { label: "FTP", keyword: "ftp", note: "File transfer. Often run with anonymous access or weak/default credentials.", defaultType: "exploit" },
  22: { label: "SSH", keyword: "ssh", note: "Remote shell access. Usually targeted via credential/login testing, not exploits.", defaultType: "auxiliary" },
  23: { label: "Telnet", keyword: "telnet", note: "Unencrypted remote shell - credentials and traffic are sent in plain text.", defaultType: "auxiliary" },
  25: { label: "SMTP", keyword: "smtp", note: "Mail transfer. Can sometimes be used to enumerate valid usernames.", defaultType: "auxiliary" },
  53: { label: "DNS", keyword: "dns", note: "Name resolution service.", defaultType: "auxiliary" },
  80: { label: "HTTP", keyword: "http", note: "Web server. Check the specific web application/software running for known issues.", defaultType: "exploit" },
  110: { label: "POP3", keyword: "pop3", note: "Mail retrieval. Often targeted via credential testing.", defaultType: "auxiliary" },
  135: { label: "MSRPC", keyword: "dcerpc", note: "Windows RPC endpoint mapper.", defaultType: "exploit" },
  139: { label: "NetBIOS/SMB", keyword: "smb", note: "Windows file sharing (legacy). Often paired with port 445.", defaultType: "exploit" },
  143: { label: "IMAP", keyword: "imap", note: "Mail retrieval. Often targeted via credential testing.", defaultType: "auxiliary" },
  443: { label: "HTTPS", keyword: "http", note: "Web server over TLS. Check the specific web application/software running.", defaultType: "exploit" },
  445: { label: "SMB", keyword: "smb", note: "Windows file sharing - a very common target for well-known exploits (e.g. EternalBlue) on unpatched systems.", defaultType: "exploit" },
  1433: { label: "MSSQL", keyword: "mssql", note: "Microsoft SQL Server. Often targeted via credential testing.", defaultType: "auxiliary" },
  1521: { label: "Oracle DB", keyword: "oracle", note: "Oracle database listener.", defaultType: "auxiliary" },
  2049: { label: "NFS", keyword: "nfs", note: "Network file sharing, can expose mounts with weak access control.", defaultType: "auxiliary" },
  3000: { label: "HTTP (dev)", keyword: "http", note: "Development web server (e.g. Node.js/React/Ruby).", defaultType: "exploit" },
  3306: { label: "MySQL", keyword: "mysql", note: "MySQL database. Often targeted via credential testing.", defaultType: "auxiliary" },
  3389: { label: "RDP", keyword: "rdp", note: "Windows Remote Desktop. A common target for credential testing and known CVEs on unpatched systems.", defaultType: "exploit" },
  5000: { label: "HTTP (Flask/dev)", keyword: "http", note: "Development web service or API server.", defaultType: "exploit" },
  5432: { label: "PostgreSQL", keyword: "postgres", note: "PostgreSQL database. Often targeted via credential testing.", defaultType: "auxiliary" },
  5900: { label: "VNC", keyword: "vnc", note: "Remote desktop. Often run with weak or no authentication.", defaultType: "auxiliary" },
  6379: { label: "Redis", keyword: "redis", note: "In-memory data store. Historically often exposed with no authentication at all.", defaultType: "exploit" },
  8000: { label: "HTTP (alt)", keyword: "http", note: "Web application or API server on port 8000.", defaultType: "exploit" },
  8080: { label: "HTTP (alt)", keyword: "http", note: "Web server, usually a proxy or application server on a non-standard port.", defaultType: "exploit" },
  8081: { label: "HTTP (alt)", keyword: "http", note: "Web server, proxy or secondary service.", defaultType: "exploit" },
  8443: { label: "HTTPS (alt)", keyword: "http", note: "Web server over TLS, non-standard port.", defaultType: "exploit" },
  27017: { label: "MongoDB", keyword: "mongodb", note: "Document database. Historically often exposed with no authentication at all.", defaultType: "auxiliary" },
};

export function suggestForPort(port: number): PortSuggestion {
  return (
    PORT_SUGGESTIONS[port] ?? {
      label: `Port ${port}`,
      keyword: String(port),
      note: "Not a well-known port - identify the actual service (e.g. by connecting to it, or with a banner-grab module) before assuming what it is.",
    }
  );
}
