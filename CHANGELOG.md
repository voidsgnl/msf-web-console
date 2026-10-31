# Changelog

## Unreleased

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
