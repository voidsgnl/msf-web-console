/**
 * Plain-language explanations for the datastore option names Metasploit
 * reuses across most modules. Metasploit's own `desc` field (shown
 * alongside this) is often terse or assumes you already know the
 * framework's conventions - this exists to translate the option's *name*
 * itself, which `desc` usually doesn't bother to do (e.g. a module's RHOSTS
 * description is often just "The target host(s)", which doesn't explain
 * what "host(s)" format Metasploit expects, or why it's different from
 * RHOST on older modules).
 *
 * Deliberately not exhaustive: this is for the handful of options that show
 * up on almost every module (see ESSENTIAL_OPTION_KEYS in ModuleBrowser),
 * not a full datastore reference. An option with no entry here just shows
 * Metasploit's own description, same as before.
 */
export const OPTION_GLOSSARY: Record<string, string> = {
  RHOSTS:
    "The target(s) to run this against. A single IP (10.0.0.5), a range (10.0.0.1-10.0.0.254), a CIDR block (10.0.0.0/24), or a hostname.",
  RHOST:
    "The single target IP address or hostname this module connects to.",
  RPORT: "The port on the target to connect to (e.g. 80 for HTTP, 445 for SMB).",
  LHOST:
    "Your own machine's IP address - the address the target connects back to once exploited. Must be reachable FROM the target, not just correct on your end. On a local lab, this is usually your attacking machine's LAN IP; over the internet, it needs to be your public, forwarded IP.",
  LPORT:
    "The port on your own machine that listens for the target's connection back to you. Pick something not already in use (4444 is Metasploit's traditional default).",
  SRVHOST:
    "The IP address this module's own temporary server (e.g. a malicious web server) listens on. Usually your machine's address, same considerations as LHOST.",
  SRVPORT: "The port that module's temporary server listens on.",
  TARGETURI: "The base URL path on the target web application (e.g. / or /app/).",
  TARGETURL: "The full target URL, including scheme and host.",
  USERNAME: "The account username to authenticate with, if the module needs credentials.",
  PASSWORD: "The account password to authenticate with, if the module needs credentials.",
  SMBUSER: "The Windows/SMB username to authenticate with.",
  SMBPASS: "The Windows/SMB password to authenticate with.",
  SSL: "Whether to connect over SSL/TLS (https/ssl) instead of plain text.",
  VHOST:
    "The virtual host header to send - needed when the target web server hosts multiple sites on the same IP and uses the Host header to tell them apart.",
  TARGET:
    "Which specific target profile to use (e.g. a particular OS/version the exploit is tuned for). Picking the wrong one is a common reason an otherwise-correct exploit fails.",
  PAYLOAD:
    "What the exploit delivers once it succeeds - usually a reverse shell or Meterpreter session back to you (LHOST/LPORT), or a command executed directly on the target.",
};

export function glossaryFor(optionKey: string): string | undefined {
  return OPTION_GLOSSARY[optionKey.toUpperCase()];
}
