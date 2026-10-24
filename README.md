# TrustVault

TrustVault is a small, server-rendered Flask application for private document sharing, explicit per-document permissions, and a searchable audit trail. Files are stored under the application instance directory, outside `static/`, and are served only by permission-checked routes.

## Requirements

- Python 3.12 or newer for the supported setup.
- Git.
- Windows PowerShell commands are shown below; the application itself is cross-platform.
- Redis for production rate limiting. Local development uses an in-memory limiter.

The current workspace machine reports Python 3.10.11. The application syntax and pinned libraries are compatible with that interpreter, but Python 3.12+ is the supported target; use the tests under 3.12 before deployment.

## Run locally on Windows

Open PowerShell in the TrustVault project folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
flask --app run.py run --debug
```

If PowerShell blocks activation, use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that PowerShell window, then activate the environment again. Open <http://127.0.0.1:5000>.

The app creates the SQLite database and private upload directory at startup:

- Database: `instance/trustvault.sqlite3`
- Uploads: `instance/uploads/`

These files are ignored by Git. To initialize explicitly or create a user from the CLI:

```powershell
flask --app run.py init-db
flask --app run.py create-user alice owner
```

The `create-user` command prompts for a password. It is hashed before storage.

## Local demo accounts
Security warning: These credentials are for local development and testing only. Never use them in production or on a publicly accessible deployment. Disable demo-account seeding and configure unique, secure credentials before deployment.

Development mode seeds these accounts once, using configurable environment passwords or the following safe demo-only defaults:

| Role | Username | Development password |
| --- | --- | --- |
| Admin | `admin` | `AdminDemo2026!` |
| Document owner | `owner` | `OwnerDemo2026!` |
| Viewer | `viewer` | `ViewerDemo2026!` |

Set `TRUSTVAULT_ADMIN_PASSWORD`, `TRUSTVAULT_OWNER_PASSWORD`, and `TRUSTVAULT_VIEWER_PASSWORD` before the first run to choose different seed passwords. Seed values do not reset existing accounts. Never use the demo passwords or development secret in production.

## Environment configuration

| Variable | Development default | Production |
| --- | --- | --- |
| `TRUSTVAULT_ENV` | `development` | Must be `production` |
| `TRUSTVAULT_SEED_DEMO_USERS` | `1` | `1` seeds three demo users; set `0` to use a separately bootstrapped admin |
| `SECRET_KEY` | Local-only fallback | Required, unique, random, and stored in a secret manager |
| `TRUSTVAULT_ADMIN_PASSWORD` | `AdminDemo2026!` | Required when seeding demo accounts |
| `TRUSTVAULT_OWNER_PASSWORD` | `OwnerDemo2026!` | Required when seeding demo accounts |
| `TRUSTVAULT_VIEWER_PASSWORD` | `ViewerDemo2026!` | Required when seeding demo accounts |
| `TRUSTVAULT_COOKIE_SECURE` | `0` for local HTTP | Production cookies are always Secure |
| `RATELIMIT_STORAGE_URI` | `memory://` | Required shared store, e.g. a protected Redis endpoint |

`.env.example` is a reference only; Flask does not automatically load it in this project. Set variables in the process environment or your deployment secret manager. For example, local PowerShell can set a demo password with `$env:TRUSTVAULT_OWNER_PASSWORD = "a-local-only-password"`.

Production startup refuses the default development secret and in-memory limiter. The three seeded accounts require a password change on first login in production. To use named accounts instead, start once with demo seeding enabled and required bootstrap secrets, create a distinct administrator with `flask --app run.py create-user`, then set `TRUSTVAULT_SEED_DEMO_USERS=0`; protect the bootstrap credentials and rotate them as part of deployment.

## Tests

```powershell
python -m pytest -q
```

The tests use temporary databases and private upload directories. They exercise login hashing and rate limiting, CSRF, role checks, upload validation, IDOR protections, permission grant/revoke, immediate post-revocation download denial, and append-only audit behavior.

## Roles and access policy

- **Admin:** manages accounts; sees document metadata, activity, and audit logs; can grant/revoke permissions on any document. Administrator status alone does not grant access to file contents.
- **Document owner:** uploads and manages metadata for owned documents; grants/revokes access to other active accounts; can delete owned documents.
- **Viewer:** can view/download only documents explicitly shared with them. A viewer role never permits editing.
- **Read permission:** view and download.
- **Edit permission:** read plus update document title/category; it does not replace the uploaded file. Viewer accounts cannot be granted edit.

Every protected document request checks the current database permission. An unauthorized or nonexistent document ID returns the same not-found response to reduce enumeration. There are no public links or bearer tokens. Admin access-control actions are centrally audited.

## Route/API map

TrustVault is an HTML form application, not a JSON API. All state-changing routes require a valid Flask-WTF CSRF token.

| Method | Route | Access / purpose |
| --- | --- | --- |
| `GET, POST` | `/login` | Sign in; limited to five attempts per minute per client IP |
| `POST` | `/logout` | Signed-in user logout |
| `GET, POST` | `/change-password` | Signed-in user password change |
| `GET` | `/dashboard` | Owner/viewer home; admins redirect to the admin overview |
| `GET` | `/documents/` | Search accessible documents; admins see metadata |
| `GET, POST` | `/documents/new` | Owner-only upload |
| `GET` | `/documents/<id>` | View metadata only with read permission |
| `GET` | `/documents/<id>/view` | Permission-checked file view |
| `GET` | `/documents/<id>/download` | Permission-checked download |
| `GET, POST` | `/documents/<id>/edit` | Owner or explicitly edit-authorized user; metadata only |
| `POST` | `/documents/<id>/delete` | Owner-only deletion |
| `GET, POST` | `/documents/<id>/permissions` | Owner or admin grant/update access |
| `POST` | `/documents/<id>/permissions/<user_id>/revoke` | Owner or admin revoke access |
| `GET` | `/admin/` | Admin counts and recent audit events |
| `GET, POST` | `/admin/users` | Admin account creation |
| `POST` | `/admin/users/<id>/update` | Admin role/status changes |
| `POST` | `/admin/users/<id>/reset-password` | Admin temporary password reset |
| `GET` | `/admin/documents` | Admin searchable metadata inventory |
| `GET` | `/admin/audit` | Admin searchable, paginated audit logs |

## Deployment notes

1. Use Python 3.12+, a production WSGI server, a TLS-terminating reverse proxy, and a shared Redis rate-limit store. Do not expose Flask's development server.
2. Configure `TRUSTVAULT_ENV=production`, a strong `SECRET_KEY`, all required seed passwords if seeding remains enabled, and `RATELIMIT_STORAGE_URI` before starting the app. Use a protected Redis URI and configure trusted proxy/network boundaries; do not trust arbitrary forwarded IP headers.
3. On Windows, Waitress is included. A basic local process command is `waitress-serve --listen=127.0.0.1:8080 --call trustvault:create_app`; production should bind only on a protected interface behind TLS.
4. Place `instance/` on a private, access-controlled persistent volume. Restrict operating-system access, encrypt backups at rest, and define retention and recovery procedures. Do not serve that directory from the web server.
5. Set the secure cookie flag (forced in production), keep the application and dependencies patched, use HTTPS, rotate secrets, monitor logs, and back up the SQLite database consistently with the files.
6. Configure external monitoring and off-host audit export if tamper evidence is required. SQLite triggers are not a cryptographic or privileged-host boundary.
7. Disable or replace seeded demo accounts after secure administrator bootstrap. Production accounts created by the built-in seed process must change their passwords at first login.

This project has not been deployed. No hosting provider, production secrets, or domain has been configured.

## Known limitations

- SQLite is suitable for a small hackathon deployment, not high write concurrency or multi-node database access. Use a managed database and migration plan before scaling.
- Audit append-only triggers prevent ordinary SQL updates/deletes but cannot stop a host administrator from modifying the database file, changing schema/triggers, or replacing backups.
- The memory-backed limiter is development-only and resets when the process restarts; production requires Redis shared across workers.
- File validation checks filename extension, browser MIME claim, size, UTF-8 text constraints, and common PDF/PNG/JPEG signatures. It is not antivirus scanning or complete format validation. Consider a malware scanner and quarantine workflow before accepting untrusted external uploads.
- Admins can inspect metadata and adjust permissions but have no implicit file-content access. Explicitly granting a permission creates an auditable access path.
- No email delivery, account self-registration, multi-factor authentication, external identity provider, or document versioning is implemented.
