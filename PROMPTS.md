# AI usage log

These entries summarize the AI-assisted work carried out for TrustVault on **2026-10-24**. They are task summaries, not claims of independent verification. The project owner should review and amend this log to match any event, institution, or submission policy.

1. **2026-10-24 — Application scaffold:** Asked the AI to create a beginner-friendly Flask/SQLite document-sharing application with Admin, Document Owner, and Viewer roles, runnable files, and a Windows setup guide.
2. **2026-10-24 — Security design:** Asked the AI to implement server-side role and per-document authorization, CSRF protection, password hashing, safe sessions, and login rate limiting. **Security-related usage.**
3. **2026-10-24 — Upload and audit controls:** Asked the AI to keep files outside public static storage, validate file type/size, use random storage names, and record document/permission/access events in an append-only SQLite audit trail. **Security-related usage.**
4. **2026-10-24 — Verification:** Asked the AI to write Pytest coverage for CSRF, authentication, upload validation, cross-user document access, grants/revocations, revoked downloads, and audit behavior.
5. **2026-10-24 — UX and operations:** Asked the AI to implement the responsive dashboard, account and audit views, threat documentation, setup/deployment guidance, and GitHub-ready files.

## Project-owner tasks — complete before submission

- **AUTHOR TO COMPLETE:** Confirm that these summaries accurately describe the prompts and AI use for the final submission; add any other tools or assistance used.
- **AUTHOR TO COMPLETE:** Check the hackathon's AI disclosure, attribution, and acceptable-use requirements and adapt this file to its required format.
- **AUTHOR TO COMPLETE:** Review every generated code and security decision; do not represent an AI-generated review or test run as an independent audit.
- **AUTHOR TO COMPLETE:** Add the date, author/submitter attribution, and any required AI-output or source attribution details.

Verification and commit notes

- Date: 2026-10-24
- Command run: "python -m pytest -q --tb=short"
- Observed result: 20 tests passed.
- What this verifies: The current automated test suite passed in the local environment. This is not an independent security audit and does not prove that every security control is effective.
- Git history: The repository history includes commit "aa940c2" on the master branch, aligned with origin/master at the time checked. This commit is not necessarily associated with every task summarized above; task-specific commit links should be added only after verifying the relevant changes.

2026-10-25 — Render deployment troubleshooting

- Problem: The initial Render deployment failed because the configured start command used Gunicorn, which was not installed.
- Observed tool output: "bash: line 1: gunicorn: command not found"
- What I checked: I inspected "requirements.txt" and found that "waitress==3.0.2" was already listed.
- Correction: I changed the Render start command to "waitress-serve --host=0.0.0.0 --port=$PORT run:app".
- Observed result: Render logs reported "INFO:waitress:Serving on http://0.0.0.0:10000" and then "Your service is live".
- What this verifies: The deployment started successfully with the revised command, and I opened the live website. This does not independently verify every security feature.
- Commit reference: No commit is claimed for this Render dashboard configuration change unless a corresponding repository change is verified.