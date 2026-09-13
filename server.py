#!/usr/bin/env python3
import json, os, re, sqlite3
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
    return conn

def classify(ua):
    device = "Mobile" if re.search(r"Mobile|Android|iPhone", ua, re.I) else "Tablet" if re.search(r"iPad|Tablet", ua, re.I) else "Desktop"
    os_name = next((name for token,name in [("Windows","Windows"),("Mac OS X","macOS"),("iPhone","iOS"),("Android","Android"),("Linux","Linux")] if token in ua), "Other")
    browser = "Edge" if "Edg/" in ua else "Chrome" if "Chrome/" in ua else "Firefox" if "Firefox/" in ua else "Safari" if "Safari/" in ua else "Other"
    return device, os_name, browser

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/api/admin/visits": return self.send_error(404)
        with db() as conn:
            rows = conn.execute("SELECT occurred_at,ip,path,referrer,device,os,browser,screen,language FROM visits ORDER BY id DESC LIMIT 500").fetchall()
        keys = ["time","ip","path","referrer","device","os","browser","screen","language"]
        data = json.dumps([dict(zip(keys, row)) for row in rows]).encode()
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
            self.send_response(204); self.end_headers()
        except Exception:
            self.send_response(204); self.end_headers()
    def log_message(self, *_): pass

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    db().close()
    ThreadingHTTPServer(("127.0.0.1", 8787), Handler).serve_forever()
