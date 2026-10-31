# Changelog

## Unreleased

- Added controlled Katana endpoint crawling with an exact approved-origin regex, redirects disabled, depth 2, a 100-page cap, a 2 requests/second limit, a 90-second crawl budget, and a 1 MiB response-size limit. Parsed endpoint method/source metadata is retained; only same-origin endpoints enter the inventory and discovered URLs never expand approved scope.
- Added the Katana runner to the Web Security workspace and tests for fixed command construction, scope boundaries, and JSONL endpoint parsing.

- Added passive Subfinder subdomain discovery using fixed arguments, a bounded runtime/output capture, and structured hostname/source parsing. Discovered subdomains are stored as out-of-scope assets and are never automatically probed or added to approved targets.
- Added frontend action and provenance display for Subfinder results, plus tests for command construction, parsing, and scope isolation.

- Added a per-assessment URL/host inventory populated from HTTP probe, httpx, and WhatWeb evidence. Assets are deduplicated, retain first/last-seen timestamps and source provenance, and are classified against approved scope without changing the approved target list.
- Added an Asset inventory panel to Web Security with separate in-scope and out-of-scope counts.
- Added tests for scope classification, approved-target non-expansion, and inventory deduplication.

- Added a platform-owned SQLite assessment store, separate from the Metasploit
  database.
- Added authenticated API endpoints to create, list, inspect, and update the
  lifecycle status of assessments.
- Added explicit target registration and removal, duplicate protection, and
  exact scheme/host/port scope validation.
- Disabled WhatWeb redirect following so a scanner run cannot silently leave its approved origin.\n- Added unit tests for assessment persistence, authorization confirmation,
  lifecycle restrictions, duplicate targets, scope boundaries, execution history,
  stored evidence retrieval, and scanner timeout persistence.

The built-in HTTP probe, httpx, and WhatWeb now require an active assessment and
an exact approved target origin. Completed executions, timeouts, and launch
failures are persisted; the Web Security workspace lists recent runs and can
reopen their stored evidence. Scanner cancellation and hard output limits remain
outstanding.
