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
      ("A new session opened — you now have remote access to the target")
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

- [ ] **"Scan a target" wizard** — enter an IP/range, the tool runs the
      right discovery modules (port scan → service version detection)
      automatically, and shows findings in plain language rather than
      requiring the user to pick scanner modules themselves.
- [ ] **Suggested next steps from scan results** — match discovered
      services/versions against known exploit modules (mirroring
      `post/multi/recon/local_exploit_suggester`'s approach) and present
      them as "here's what might work here," ranked by rank/reliability.
- [ ] **Recipes** — a small library of named, pre-filled workflows for
      common teaching/lab scenarios (e.g. "exploit a vulnerable FTP
      service"), so a first-time user has something concrete to run and
      learn from rather than a blank module browser.

## Phase 3 — Safety rails

A novice using an exploitation framework without any friction is a real risk
to themselves and to whatever they're pointed at.

- [ ] Confirmation step before executing anything flagged `Privileged` or
      with destructive `SideEffects` (`CONFIG_CHANGES`, `ARTIFACTS_ON_DISK`
      etc. — already in the module metadata, currently unused by the UI)
- [ ] A visible reminder, enforced in the UI copy (not a legal disclaimer
      buried in a README), that targets must be owned or authorized
- [ ] "Check first" nudging — prefer a module's `check` action over a full
      `run` where Metasploit supports it, and explain the difference

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
