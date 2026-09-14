#!/usr/bin/env python3
import ipaddress, json, os, re, sqlite3, threading, urllib.parse, urllib.request
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.join(os.path.dirname(__file__), "public")
DB = os.environ.get("AGENTREINS_ANALYTICS_DB", "/var/lib/agentreins-web/analytics.sqlite3")

def db():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS visits(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL,
      ip TEXT NOT NULL, path TEXT NOT NULL, referrer TEXT, user_agent TEXT, device TEXT, os TEXT,
      browser TEXT, screen TEXT, language TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS downloads(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL,
      ip TEXT NOT NULL, architecture TEXT NOT NULL, referrer TEXT, user_agent TEXT, device TEXT,
      os TEXT, browser TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS geo_cache(ip TEXT PRIMARY KEY, country TEXT, region TEXT,
      city TEXT, asn TEXT, organization TEXT, updated_at TEXT NOT NULL)""")
    return conn

def enrich_ip(value):
    try:
        address = ipaddress.ip_address(value)
        if not address.is_global: return
        with db() as conn:
            cached = conn.execute("SELECT 1 FROM geo_cache WHERE ip=? AND updated_at>?", (value, (datetime.now(timezone.utc)-timedelta(days=30)).isoformat())).fetchone()
        if cached: return
        url = "https://ipwho.is/" + urllib.parse.quote(value) + "?fields=success,ip,country,region,city,connection"
        request = urllib.request.Request(url, headers={"User-Agent":"AgentReins-Website/1.0"})
        with urllib.request.urlopen(request, timeout=4) as response: payload = json.load(response)
        if not payload.get("success"): return
        connection = payload.get("connection") or {}
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO geo_cache(ip,country,region,city,asn,organization,updated_at) VALUES(?,?,?,?,?,?,?)",
                (value, payload.get("country"), payload.get("region"), payload.get("city"),
                 connection.get("asn"), connection.get("org") or connection.get("isp"), datetime.now(timezone.utc).isoformat()))
    except Exception: pass

def enrich_later(value): threading.Thread(target=enrich_ip, args=(value,), daemon=True).start()

def backfill_geo():
    with db() as conn:
        values = [row[0] for row in conn.execute("SELECT ip FROM visits UNION SELECT ip FROM downloads").fetchall()]
    for value in values: enrich_ip(value)

def classify(ua):
    device = "Mobile" if re.search(r"Mobile|Android|iPhone", ua, re.I) else "Tablet" if re.search(r"iPad|Tablet", ua, re.I) else "Desktop"
    os_name = next((name for token,name in [("Windows","Windows"),("Mac OS X","macOS"),("iPhone","iOS"),("Android","Android"),("Linux","Linux")] if token in ua), "Other")
    browser = "Edge" if "Edg/" in ua else "Chrome" if "Chrome/" in ua else "Firefox" if "Firefox/" in ua else "Safari" if "Safari/" in ua else "Other"
    return device, os_name, browser

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/download/apple-silicon", "/download/intel"):
            architecture = "Apple Silicon" if self.path.endswith("apple-silicon") else "Intel"
            ua = self.headers.get("user-agent", "")[:512]
            device, os_name, browser = classify(ua)
            ip = (self.headers.get("x-real-ip") or self.client_address[0])[:64]
            with db() as conn:
                conn.execute("DELETE FROM downloads WHERE occurred_at < ?", ((datetime.now(timezone.utc)-timedelta(days=30)).isoformat(),))
                conn.execute("INSERT INTO downloads(occurred_at,ip,architecture,referrer,user_agent,device,os,browser) VALUES(?,?,?,?,?,?,?,?)",
                    (datetime.now(timezone.utc).isoformat(), ip, architecture, self.headers.get("referer", "")[:1024], ua, device, os_name, browser))
            enrich_later(ip)
            filename = "AgentReins-Apple-Silicon.dmg" if architecture == "Apple Silicon" else "AgentReins-Intel.dmg"
            self.send_response(302); self.send_header("Location", f"/downloads/{filename}"); self.send_header("Cache-Control", "no-store"); self.end_headers(); return
        if self.path != "/api/admin/stats": return self.send_error(404)
        with db() as conn:
            visits = conn.execute("""SELECT v.occurred_at,v.ip,v.path,v.referrer,v.device,v.os,v.browser,v.screen,v.language,
              g.country,g.region,g.city,g.asn,g.organization FROM visits v LEFT JOIN geo_cache g ON g.ip=v.ip ORDER BY v.id DESC LIMIT 500""").fetchall()
            downloads = conn.execute("""SELECT d.occurred_at,d.ip,d.architecture,d.referrer,d.device,d.os,d.browser,
              g.country,g.region,g.city,g.asn,g.organization FROM downloads d LEFT JOIN geo_cache g ON g.ip=d.ip ORDER BY d.id DESC LIMIT 500""").fetchall()
            summary = conn.execute("""SELECT
              (SELECT count(*) FROM visits),
              (SELECT count(DISTINCT ip) FROM (SELECT ip FROM visits UNION ALL SELECT ip FROM downloads)),
              (SELECT count(*) FROM downloads),
              (SELECT count(*) FROM downloads WHERE architecture='Apple Silicon'),
              (SELECT count(*) FROM downloads WHERE architecture='Intel')""").fetchone()
        visit_keys = ["time","ip","path","referrer","device","os","browser","screen","language","country","region","city","asn","organization"]
        download_keys = ["time","ip","architecture","referrer","device","os","browser","country","region","city","asn","organization"]
        data = json.dumps({"summary":dict(zip(["visits","uniqueIPs","downloads","appleSilicon","intel"],summary)),
                           "visits":[dict(zip(visit_keys,row)) for row in visits],
                           "downloads":[dict(zip(download_keys,row)) for row in downloads]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        if self.path != "/api/visit": return self.send_error(404)
        try:
            length = min(int(self.headers.get("content-length", "0")), 4096)
            body = json.loads(self.rfile.read(length) or b"{}")
            ua = self.headers.get("user-agent", "")[:512]
            device, os_name, browser = classify(ua)
            ip = (self.headers.get("x-real-ip") or self.client_address[0])[:64]
            with db() as conn:
                conn.execute("DELETE FROM visits WHERE occurred_at < ?", ((datetime.now(timezone.utc)-timedelta(days=30)).isoformat(),))
                conn.execute("INSERT INTO visits(occurred_at,ip,path,referrer,user_agent,device,os,browser,screen,language) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (datetime.now(timezone.utc).isoformat(), ip, str(body.get("path","/"))[:512], str(body.get("referrer") or "")[:1024], ua, device, os_name, browser, str(body.get("screen") or "")[:32], str(body.get("language") or "")[:32]))
            enrich_later(ip)
            self.send_response(204); self.end_headers()
        except Exception:
            self.send_response(204); self.end_headers()
    def log_message(self, *_): pass

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    db().close()
    threading.Thread(target=backfill_geo, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 8787), Handler).serve_forever()
