# TrustVault threat model

**Scope:** the Flask application, its browser sessions, SQLite database, and private upload directory. This is a practical baseline for a hackathon application, not an independent security certification. Review this document before any public deployment.

## Assets and trust boundaries

- Uploaded document bytes and their metadata.
- User credentials, role assignments, session cookies, and per-document permissions.
- Audit events and their actor/action/target/outcome metadata.
- The host filesystem, SQLite database, environment secrets, and Redis limiter endpoint.
- The browser-to-application boundary, where IDs, form fields, filenames, MIME claims, and requests are untrusted.

## Threats, mitigations, and remaining risk

| Threat | Mitigations in this implementation | Residual risk / operational action |
| --- | --- | --- |
| Credential theft or brute-force login | Werkzeug password hashes; generic login error; five-attempt-per-minute IP limiter; production shared limiter required; session cleared on login/logout; short session lifetime | No MFA, password breach check, lockout notification, or account recovery. Protect Redis and secrets; use unique strong passwords. |
| CSRF or forged state changes | Flask-WTF CSRF protection on all forms; SameSite=Lax cookie; state changes use POST | XSS or a compromised browser can still act as the user. Keep templates escaped and JavaScript self-hosted. |
| Cross-user IDOR or unauthorized read/download | Server-side owner/permission lookup on every detail, view, download, edit, delete, and permission route; indistinguishable 404 for inaccessible document IDs; revoked grants are read from SQLite live | Authorization remains dependent on correct application and database behavior. Add tests whenever routes are added. |
| Viewer privilege escalation | Server-enforced role restrictions; viewer cannot edit; owner/admin checks for permission administration and deletion; admin content access requires explicit grant | Administrators can grant themselves permission; this is explicit and auditable by policy, but application-admin trust is still required. |
| Malicious or oversized upload | 10 MiB request and database constraints; allow-listed extensions; MIME claim/signature checks for PDF/PNG/JPEG; UTF-8/control-character checks for text; random storage IDs; files outside static | Signature checks are not full parsers, malware scans, or decompression-bomb defenses. Run scanning/quarantine before public use. |
| Path traversal or filename-based storage attack | Client filenames are sanitized for display/download only; internal names are random UUID hex; storage paths are built under a private configured folder | Protect the upload directory from local users and ensure the production web server never maps it to a public route. |
| Session theft or transport interception | HttpOnly and SameSite=Lax cookies; Secure cookies forced in production; short session lifetime; HTTPS required operationally | Local HTTP is intentionally insecure for transport. Use TLS, safe proxy configuration, and secret rotation. |
| Audit-log forgery or repudiation | Events inserted by a central helper; DB triggers reject ordinary UPDATE/DELETE; audit rows include actor, action, target, UTC timestamp, outcome, and bounded safe context; secrets/content excluded | SQLite is not tamper-proof: a privileged filesystem/database operator can replace the file, remove triggers, or rewrite history. No hash chain, signature, remote witness, or immutable backup is implemented. Export to an access-controlled remote append-only service for stronger evidence. |
| Sensitive information exposed through logs | No passwords, session IDs, or file contents are written; failed-login context keeps only a truncated username; upload context contains a filename and byte count | Filenames/usernames may themselves be sensitive; apply retention, access controls, and privacy review. |
| Database constraint bypass or inconsistent writes | SQLite foreign keys enabled per connection; role/permission/size constraints; route writes and audit events share SQLite transactions; user accounts are deactivated instead of deleted | Direct host-level DB access bypasses application authorization and can alter schema. SQLite has limited concurrent write throughput. |
| Admin account misuse | Separate admin role; admin routes guarded server-side; administrator content is not implicit; role changes prevent removal of the last active admin; administrative actions audited | An admin can manage users/permissions. Require trusted operators, MFA/SSO in production, monitoring, and a break-glass procedure. |
| Dependency or host compromise | Compatible pinned direct dependencies; private file storage; CSP and common response headers | Pinning does not replace updates, vulnerability scanning, backups, patching, TLS, host hardening, or independent review. |

## Data-flow decisions

1. Authentication resolves an active database user; the session stores only the numeric account ID. Password hashes use Werkzeug's maintained hashing helpers.
2. A document ID is a selector, never proof of access. Routes verify the current user's ownership/permission before metadata/content operations and again before serving bytes.
3. Upload names are treated as display metadata. The disk name is generated internally and the folder is not under `static/`.
4. Audit context is structured and intentionally small. Audit target document IDs are historical identifiers rather than foreign keys so deleting a document does not erase its historical target; delete events also snapshot the title and safe filename in context.
5. SQLite transactions commit each request's database changes together; upload creation explicitly commits metadata and audit before returning success. A crash between filesystem write and DB commit may leave an orphaned file; operational cleanup/monitoring is not yet implemented.

## SQLite audit limitations

Append-only triggers protect against accidental or ordinary application SQL mutation, not a privileged actor. SQLite has no built-in immutable table, tamper-evident ledger, cryptographic signatures, or independent time source. The application uses UTC system timestamps, and the host clock can be wrong. For evidentiary use, ship events to a separately administered append-only log service, apply retention controls, monitor export gaps, and periodically verify signed checkpoints.

## Before production

- Obtain an independent security review and run the suite on the supported Python 3.12+ runtime.
- Use TLS, a strong secret manager, Redis-backed rate limiting, restricted filesystem permissions, encrypted backups, and operational monitoring.
- Decide retention/legal basis for usernames, filenames, audit events, and backups; define incident response and key rotation.
- Add malware scanning/quarantine, account MFA or SSO, secure password reset, and external tamper-evident audit export if required by the data classification.
- Verify reverse-proxy behavior, request size/time limits, proxy trust, secure cookies, backup restore, and permission revocation under production topology.
