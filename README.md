# AgentReins Website

The English launch website for AgentReins at `www.chuhaijian.com`.

## Release downloads

Upload notarized builds using these exact paths; the homepage buttons are already wired to them:

- `/opt/agentreins-web/public/downloads/AgentReins-Apple-Silicon.dmg`
- `/opt/agentreins-web/public/downloads/AgentReins-Intel.dmg`

## Local preview

```bash
python3 server.py
```

Serve `public/` with any static server and run `server.py` on port 8787 for visit collection.

## Analytics

Visit events are stored in SQLite with a 30-day raw-data retention policy. The schema records time, IP address, page, referrer, user agent, device class, operating system, browser, screen size, and language. It deliberately does not collect cookies or page input.

Example local report:

```bash
sqlite3 /var/lib/agentreins-web/analytics.sqlite3 \
  'select occurred_at, ip, device, os, browser, path, referrer from visits order by id desc limit 50;'
```

The authenticated dashboard is available at `/admin/`. Both the page and its JSON endpoint are protected by Nginx Basic Authentication; the SQLite file is never served directly.
