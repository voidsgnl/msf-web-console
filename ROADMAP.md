# Roadmap: making this usable without Metasploit experience

## The goal

The point of a web UI over Metasploit isn't just "clicking instead of typing
commands" — msfconsole already has tab-completion, `info`, `show options`,
and help text. The actual goal is to remove the need to already *know*
Metasploit (and offensive security concepts in general) to get something
useful done with it.

Today (see [Status](README.md#status)) the tool does the first part well:
browse modules, fill in options, execute, track jobs/sessions, read results,
explore the database. That's real progress and the UI mechanics are solid.
It does **not** yet do the second part. A person who doesn't know what
`RHOSTS`, `LHOST`, "payload", or "session" mean will hit a wall immediately
— the tool hands them Metasploit's own vocabulary and assumes they already
have the mental model of how an exploit, a listener, and a reverse
connection fit together.

This roadmap is about closing that gap, in phases, without turning the tool
into a toy that hides what's actually happening (a security tool that lies
about what it's doing is worse than one that's hard to use).

## Phase 0 — Foundation (done)

The UI shell needed to be trustworthy before anything built on top of it
would matter:

- Module browser, options editor, payload selection, job/session tracking
- Views persist across navigation instead of resetting (a module run, a job
  detail panel, and search state now survive switching tabs)
- Live run-status with an elapsed timer and a direct link to Jobs, instead of
  a flat 90s timeout that read like a failure
- Jobs view surfaces when a job disappears (completed/stopped) instead of
  silently vanishing
- Sessions view explains *why* nothing shows up yet instead of a bare empty
  state
- Styled confirmation dialogs instead of native browser `confirm()` popups

## Phase 1 — Plain-language layer (done)

Make the *existing* flow (browse → configure → run → read result)
understandable without already knowing Metasploit's vocabulary. No new
workflows yet — just translate what's already there.

- [x] **Option glossary** — a plain-English explanation for the common
      datastore options (`RHOSTS`, `LHOST`, `LPORT`, `SRVPORT`, `TARGETURI`,
      `SSL`, credentials, …) shown alongside Metasploit's own description,
      not replacing it. Someone can learn what `LHOST` *means* instead of
      just being told it's required.
- [x] **Result interpreter** — translate the raw "completed" / job-id /
      session-list outcome of a run into a one-line plain-English verdict
      ("A new session opened - you now have remote access to the target")
      instead of leaving the user to infer success from a status pill.
- [x] **Module one-liners** — a "Quick summary" box combining a generic,
      accurate explanation of the module *type* with the module's own first
      sentence of description (pulled verbatim, not fabricated), shown
      before the full dense description.
- [x] **Inline risk/impact labels** — a module's `Rank` (color-coded by
      reliability), `Privileged`, and `SideEffects` notes (already returned
      by the RPC, previously buried in the Advanced tab) now show as visible
      badges in the module header, before execution rather than after.

## Phase 2 — Guided workflows

The real skill gap in Metasploit isn't "which button do I click" — it's
"which module do I even need." That requires a guided path, not just a
better module browser.

- [x] **"Scan a target" wizard (v1)** — enter an IP/range/CIDR, the tool
      runs Metasploit's TCP port scanner automatically and lists open ports
      with a plain-language guess at what's likely running on well-known
      ones - no scanner module picking required. The guess is explicitly
      labeled as port-number-based, not a confirmed service identification
      (the port scanner alone doesn't fingerprint services - see note
      below).
- [x] **Real service version detection** — a "Confirm service versions"
      action chains in the actual protocol-specific scanner modules
      (`scanner/ftp/ftp_version`, `scanner/ssh/ssh_version`,
      `scanner/smtp/smtp_version`, `scanner/http/http_version`,
      `scanner/pop3/pop3_version`, `scanner/imap/imap_version`,
      `scanner/smb/smb_version`, `scanner/mysql/mysql_version`,
      `scanner/rdp/rdp_scanner`, `scanner/postgres/postgres_version`,
      `scanner/redis/redis_server`, `scanner/telnet/telnet_version`) for
      each open port with a known mapping, and labels the result
      "Confirmed" with the actual banner/version text once the module
      reports it - replacing the port-number guess rather than hiding it.
      Ports without a reliable single-module mapping (e.g. MSSQL, whose
      version check queries a different UDP port; or services with no
      dedicated version-scanner module) keep the existing guess, clearly
      labeled as unconfirmed.
- [x] **Suggested next steps from scan results** — `GET /api/modules/suggest`
      matches a CONFIRMED service banner (not the port-number guess) against
      Metasploit's own module names and ranks the candidates by Metasploit's
      own Rank - mirroring the spirit of
      `post/multi/recon/local_exploit_suggester` without its most intrusive
      step. A name/description match is labeled as just that, not a
      confirmed vulnerability - `POST /api/modules/{type}/{name}/check`
      actually runs the module's own `check` against the live target (the
      same mechanism `local_exploit_suggester` uses internally) and returns
      a verdict, surfaced in the Scan wizard as a per-candidate "Verify"
      button rather than run automatically.
- [x] **Recipes** — a small library of named, pre-filled workflows for
      common teaching/lab scenarios (e.g. "exploit a vulnerable FTP
      service"), so a first-time user has something concrete to run and
      learn from rather than a blank module browser.

## Phase 3 — Safety rails (implemented; live verification pending)

A novice using an exploitation framework without any friction is a real risk
to themselves and to whatever they're pointed at.

- [x] Confirmation step before executing anything flagged `Privileged` or
      with destructive `SideEffects` (`CONFIG_CHANGES`, `ARTIFACTS_ON_DISK`
      etc.). The dialog lists the module's specific higher-impact flags;
      informational side effects remain visible without triggering a
      destructive-action confirmation.
- [x] Visible authorization reminders in the module execution workflow and
      Recipes view. The reminder appears beside the action, not only in docs.
- [x] "Check first" guidance — exploit and auxiliary modules expose an
      explicit `Check first` action where the module supports Metasploit's
      `check` convention. The UI explains that checks still contact the
      target, displays vulnerable / not-vulnerable / inconclusive results,
      and keeps full execution as a separate user action. The Scan wizard's
      per-candidate Verify action uses the same module check endpoint.

## Execution Reliability — foundation track (in progress)

Execution tracking is a correctness requirement, not just a status indicator.
The UI must not claim success or failure when Metasploit has not provided
evidence for either outcome. This foundation track is being addressed before
the next guided workflow phase; it does not renumber the planned phases below.

- [x] Treat repeated result-fetch failures as **outcome unverified**, not as
      confirmed module execution failures.
- [x] Treat a job disappearing without a retrievable result as **outcome
      unverified**, not as confirmed completion.
- [x] Make the tracking time limit explicitly observational: it stops UI
      polling only and never cancels the Metasploit job.
- [ ] Verify behavior against the user's installed Metasploit Framework and
      document which result-tracking RPC methods that version supports.
- [ ] Add focused regression tests for unsupported result RPCs, transient
      missing results, job disappearance, and long-running modules.
- [ ] Improve fallback tracking and expose the evidence source for each
      terminal or unverified status.

## Phase 4 — Post-exploitation guidance

- [ ] A plain-language "what can I do now" panel attached to a new session
      (meterpreter vs. shell get different suggested next actions)
- [ ] Session type explainer (what *is* a meterpreter session vs. a shell,
      shown once, contextually, not as a wall of docs)

## Phase 5 — Onboarding polish

- [ ] First-run walkthrough of the five views and what each is for
- [ ] A persistent "glossary" panel reachable from anywhere in the UI

---

Phases are sequential by design — plain language has to land before guided
workflows are worth building on top of it, and guided workflows have to
exist before safety rails around "which action is risky" make sense. Each
phase ships as its own PR(s); checkboxes above track progress.
