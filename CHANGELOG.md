# Changelog

## Unreleased

- Added a platform-owned SQLite assessment store, separate from the Metasploit
  database.
- Added authenticated API endpoints to create, list, inspect, and update the
  lifecycle status of assessments.
- Added explicit target registration and removal, duplicate protection, and
  exact scheme/host/port scope validation.
- Added unit tests for assessment persistence, authorization confirmation,
  lifecycle restrictions, duplicate targets, and scope boundaries.

The scanner UI is not yet connected to assessment scope. Reconnaissance
execution must be bound to an assessment and an approved target before this
foundation is considered complete.
