- Fixed Gobuster compatibility with packaged versions that reject the optional `-l` output flag. Directory enumeration no longer passes that flag; response-size parsing remains optional when the installed version emits it.

# Changelog

## Unreleased

- Made reconnaissance integration status explicit. The tool catalogue now distinguishes an installed binary from an implemented execution adapter; only httpx, WhatWeb, passive Subfinder, controlled Katana, and Gobuster directory mode are marked runnable. Other catalogued tools display as not integrated even if their executable is present, and cannot be launched from the UI. Added regression coverage for this distinction.

- Replaced unbounded temporary-file scanner output with concurrent pipe draining and a combined stdout/stderr capture ceiling. Excess output is discarded and terminates the scanner process group; wall-clock timeouts also terminate the process group so child processes do not continue after a timed-out run. Added regression tests for output caps and timeout handling.


- Manual path baseline collection now reports attempted, successful, and failed random-path samples with failure reasons. If all baseline probes fail, response classification is explicitly marked unavailable rather than leaving HTTP observations ambiguously unclassified; the Gobuster card displays baseline health and per-record classification labels.

- Added random-path response baselining to manual path checks. Three bounded same-origin random paths are compared with analyst-supplied responses using normalized body fingerprints, token-shingle similarity, matching status/content type, and shared not-found markers. Strong matches are labelled likely soft 404; distinct responses remain unconfirmed observations. Baseline counts and per-record comparison evidence are retained, with redirects disabled and concurrency capped at two.

- Made `MSF_WEB_WORDLIST_DIRS` authoritative when explicitly set, preventing host-installed wordlists from leaking into configured catalogs and keeping catalog results deterministic. Default project/system wordlist roots remain active when the variable is unset.


- Kept analyst-supplied manual path checks in execution evidence without automatically promoting each tested URL into the asset inventory. The approved target remains inventoried, and the inventory is rebuilt from retained evidence when viewed so paths promoted by older versions are removed. Added regression coverage confirming manual observations remain accessible in execution history.


- Consolidated Gobuster wordlist enumeration and analyst-supplied path checks behind one input-mode selector and one Run Gobuster action. Wordlist mode uses the selected backend wordlist and extensions; manual mode sends the entered relative paths through the existing bounded, same-origin GET checker. The separate Check paths action has been removed.

- Reworked the Gobuster card into compact horizontal controls with independently collapsible settings and manual path-check sections. Manual paths now use a properly sized editable textarea and accept comma-separated or newline-separated entries. The check action remains available once paths are entered and reports missing authorization, assessment, target, or scope prerequisites inline instead of appearing mysteriously disabled; results are collapsible too.

- Added a manual path-entry option directly inside the Gobuster tool card. Analysts can type up to 25 known relative paths (one per line) and check them without selecting a wordlist. Results show HTTP status, title, content type, response size, redirect destination, classification notes, and an expandable text-only preview capped at 800 characters. Checks are limited to the approved origin, use at most two concurrent GET requests, do not follow redirects, and are saved as assessment evidence.

- Grouped Gobuster likely soft-404 results by a stable response key derived from HTTP status, normalized page title, media type, and shared not-found markers. Matching paths now appear in collapsible groups with per-path status, response size, similarity, and classification evidence preserved; distinct response signatures remain separate. Added backend coverage for group separation across title and media-type differences.

- Expanded Gobuster response classification to recognize application-level soft 404s. Normalized random-path baselines now record common not-found phrases; a phrase repeated across multiple baselines and a candidate is labelled "likely soft 404". Responses in the 80–92% similarity band are labelled "needs verification" rather than being presented as distinct discoveries. Existing wildcard, distinct-response, and unverified outcomes remain available, and the Directories UI shows the additional counts.

- Fixed Gobuster wildcard preflight fidelity: random baseline paths now use the same UUID format Gobuster itself uses, avoiding path-shape-dependent soft-404 responses that could cause Gobuster to reject the scan even when a measured exclusion was supplied.

- Fixed Gobuster scans against applications that return `200` for nonexistent paths by probing five random same-origin paths and passing the observed decoded response-length range to Gobuster's `--exclude-length`. Measuring decoded bytes avoids compression mismatches, while a range handles transient wildcard-body variations between probe and scan. The probes do not follow redirects and fail explicitly if a safe wildcard baseline cannot be established.
- Fixed Gobuster's default `404` status-code blacklist conflicting with the configured status-code allowlist by explicitly clearing the blacklist. This preserves the original accepted status codes and scan scope.
- Expanded evidence management into an assessment-wide findings and evidence workspace with global search, tool/category/review filters, sorting, multi-select bulk review/dismiss/restore/classification/deletion, clipboard copy, JSON/CSV export, and a dedicated record-detail panel with editable analyst notes. Records are explicitly classified as evidence by default; analysts may promote selected records to findings without implying automatic vulnerability verification. Added run-to-run added/removed/unchanged comparison and historical activity summaries by tool.

- Added repository-local wordlist discovery from the Git-ignored root `wordlists/` directory, so downloaded SecLists data stays in the project working tree without being committed. Fixed recursive discovery depth so the documented `wordlists/SecLists/Discovery/Web-Content` directory is included, and made `MSF_WEB_WORDLIST_DIRS` additive instead of hiding the default locations.
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
