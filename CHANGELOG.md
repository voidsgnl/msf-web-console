# Changelog

## Unreleased

- Added repository-local wordlist discovery from the Git-ignored root `wordlists/` directory, so downloaded SecLists data stays in the project working tree without being committed.
- Added Gobuster directory/file enumeration as a fixed adapter. It requires explicit authorization and an exact approved origin, uses backend-configured wordlists rather than browser-supplied filesystem paths, validates optional extensions, caps concurrency at two workers with a 500 ms delay and 8-second request timeout, does not follow redirects, parses matching paths/status/response sizes, and persists results in the assessment evidence store. DNS and virtual-host modes are intentionally not enabled.

- Added persistent reconnaissance evidence management: records now have stable identifiers and can be marked reviewed, annotated with analyst notes, dismissed/restored, or permanently deleted without deleting their parent execution history. Dismissed records are hidden by default and can be shown again. Asset inventory is rebuilt from remaining evidence after permanent deletion so removed-only discoveries do not linger.

- Improved Katana classification for Next.js image/static resources and framework redirects. Malformed raw or encoded-backslash candidates are rejected before crawling with Katana's `-cos` crawl-out-scope, filtered from emitted output with `-fr`, and hidden from the default inventory while retaining script-text provenance and legitimate script-derived endpoints as evidence.

- Improved Katana result quality: classify pages, API candidates, redirects, static assets, and unverified discoveries; deduplicate identical method/URL observations while retaining query variants; flag malformed encoded-backslash paths; hide static assets and malformed URLs from the default result view while retaining classified evidence. Added result counts and a show-all control.

- Updated Katana redirect handling: the approved entry URL may follow up to five redirects only when scheme, hostname, and effective port remain identical. Cross-origin redirects are blocked and exposed as evidence; page-level crawler redirects remain disabled. Removed Katana `-ns` because it disables default host scoping. Corrected JSONL parsing to read source/tag/attribute from the nested request and capture response `Location` headers.
- Added controlled Katana endpoint crawling with an exact approved-origin regex, same-origin entry redirects resolved by a bounded preflight and page-level redirects disabled, depth 3 with JavaScript endpoint extraction and query-variant deduplication, a 100-page cap, a 2 requests/second limit, a 90-second crawl budget, and a 1 MiB response-size limit. Parsed endpoint method/source metadata is retained; only same-origin endpoints enter the inventory and discovered URLs never expand approved scope.
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
