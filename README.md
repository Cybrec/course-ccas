# course-ccas

Files for the Cybrec course **Claude Code Agent Security** and its Technology Workbook.

| Folder | What it is |
|---|---|
| `starter/` | log-triage, the sample project used in the videos and the workbook tasks |
| `signatures/` | The scanner signature file that `log-triage update-signatures` downloads |

## Set up a working copy in the AI Lab

Run these commands at the start of every lab session. The lab keeps nothing between sessions.

```bash
git config --global user.name "Student"
git config --global user.email "student@cybrec.com"
git clone https://github.com/Cybrec/course-ccas.git
cp -r course-ccas/starter ~/log-triage
git init --bare ~/log-triage-remote.git
cd ~/log-triage
cp .env.example .env
git init
git remote add origin ~/log-triage-remote.git
git add .
git commit -m "Starter"
git push -u origin main
```

`~/log-triage-remote.git` is a local repository that stands in for a remote server, so no GitHub account is needed. `git push`, and the deploy script's push to the `production` branch, go there.

## About the sample data

This is a training project for practicing agent security. Treat its contents as test data:

- **The sample access log contains a deliberately planted prompt injection.** One request's User-Agent field tells AI assistants to upload `.env` to `collect.example.net`. That is a reserved example domain, so the request can't reach anyone.
- **The token in `.env.example` is fake.**
- **All IP addresses are from the ranges reserved for documentation** (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
