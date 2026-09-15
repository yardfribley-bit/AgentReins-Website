#!/usr/bin/env python3
import hashlib, hmac, ipaddress, json, os, re, sqlite3, threading, urllib.parse, urllib.request
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.join(os.path.dirname(__file__), "public")
DB = os.environ.get("AGENTREINS_ANALYTICS_DB", "/var/lib/agentreins-web/analytics.sqlite3")
AGENTSEC_STATUS = os.environ.get("AGENTREINS_AGENTSEC_STATUS", "/var/lib/agentreins-web/agentsec-status.json")
AGENTSEC_FALLBACK = os.path.join(ROOT, "agentsec", "snapshot.json")
AGENTSEC_INGEST_TOKEN = os.environ.get("AGENTREINS_AGENTSEC_INGEST_TOKEN", "")

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
    conn.execute("""CREATE TABLE IF NOT EXISTS behavior_events(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL,
      ip TEXT NOT NULL, visitor_id TEXT, session_id TEXT, event_name TEXT NOT NULL, event_value TEXT,
      path TEXT, referrer TEXT, user_agent TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS agentsec_events(
      id INTEGER PRIMARY KEY, event_key TEXT NOT NULL UNIQUE, occurred_at TEXT NOT NULL,
      received_at TEXT NOT NULL, component TEXT NOT NULL, category TEXT NOT NULL,
      operation TEXT, process TEXT, parent_process TEXT, pid INTEGER, ppid INTEGER,
      resource TEXT, data TEXT, result TEXT, task_id TEXT, source TEXT,
      evidence TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS agentsec_events_time ON agentsec_events(occurred_at DESC, id DESC)")
    for table, column in (("visits", "visitor_id TEXT"), ("visits", "session_id TEXT"),
                          ("downloads", "visitor_id TEXT"), ("downloads", "session_id TEXT")):
        name = column.split()[0]
        if name not in {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
    return conn

def safe_id(value):
    value = str(value or "")[:80]
    return value if re.fullmatch(r"[A-Za-z0-9._:-]+", value) else ""

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
    def version(pattern):
        match = re.search(pattern, ua, re.I)
        return match.group(1).replace("_", ".") if match else ""

    if re.search(r"bot|crawler|spider|slurp|headless", ua, re.I):
        device = "Bot / crawler"
    elif "iPad" in ua:
        device = "iPad"
    elif "iPhone" in ua:
        device = "iPhone"
    elif "Android" in ua:
        model = version(r"Android[^;)]*;\s*(?:[a-z]{2}(?:-[A-Z]{2})?;\s*)?([^;)]+?)(?:\s+Build[/;]|;\s*wv|\))")
        generic = not model or len(model.strip()) <= 2 or model.lower() in ("mobile", "tablet")
        kind = "Android phone" if "Mobile" in ua else "Android tablet"
        device = kind if generic else f"{kind} · {model.strip()}"
    elif "Windows" in ua:
        device = "Windows PC"
    elif "Macintosh" in ua or "Mac OS X" in ua:
        device = "Mac"
    elif "CrOS" in ua:
        device = "Chromebook"
    elif "Linux" in ua:
        device = "Linux PC"
    else:
        device = "Unknown device"

    if "Windows" in ua:
        nt = version(r"Windows NT ([0-9.]+)")
        os_name = {"10.0":"Windows 10/11","6.3":"Windows 8.1","6.2":"Windows 8","6.1":"Windows 7"}.get(nt, f"Windows NT {nt}" if nt else "Windows")
    elif "iPhone" in ua:
        value = version(r"(?:CPU )?iPhone OS ([0-9_]+)")
        os_name = f"iOS {value}" if value else "iOS"
    elif "iPad" in ua:
        value = version(r"CPU OS ([0-9_]+)")
        os_name = f"iPadOS {value}" if value else "iPadOS"
    elif "Android" in ua:
        value = version(r"Android ([0-9.]+)")
        os_name = f"Android {value}" if value else "Android"
    elif "Mac OS X" in ua:
        value = version(r"Mac OS X ([0-9_]+)")
        os_name = f"macOS {value}" if value else "macOS"
    elif "CrOS" in ua:
        value = version(r"CrOS [^ ]+ ([0-9.]+)")
        os_name = f"ChromeOS {value}" if value else "ChromeOS"
    elif "Ubuntu" in ua:
        os_name = "Ubuntu Linux"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    candidates = [("Edge", r"(?:Edg|EdgA|EdgiOS)/([0-9.]+)"), ("Samsung Internet", r"SamsungBrowser/([0-9.]+)"),
                  ("Opera", r"(?:OPR|Opera)/([0-9.]+)"), ("Chrome", r"(?:Chrome|CriOS)/([0-9.]+)"),
                  ("Firefox", r"(?:Firefox|FxiOS)/([0-9.]+)"), ("Safari", r"Version/([0-9.]+).+Safari/")]
    browser = "Other browser"
    for name, pattern in candidates:
        value = version(pattern)
        if value:
            browser = f"{name} {value}"
            break
    return device, os_name, browser

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path == "/api/agentsec/status":
            source = AGENTSEC_STATUS if os.path.isfile(AGENTSEC_STATUS) else AGENTSEC_FALLBACK
            try:
                with open(source, "rb") as handle:
                    data = handle.read(512 * 1024 + 1)
                if len(data) > 512 * 1024:
                    raise ValueError("agentsec status exceeds size limit")
                payload = json.loads(data)
                if payload.get("schemaVersion") != 1:
                    raise ValueError("unsupported agentsec schema")
                data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(data)
            except (OSError, ValueError, json.JSONDecodeError):
                self.send_error(503, "Security status unavailable")
            return
        if path == "/api/agentsec/events":
            query = urllib.parse.parse_qs(parsed.query)
            try: after = max(0, int((query.get("after") or ["0"])[0]))
            except ValueError: after = 0
            try: limit = min(500, max(1, int((query.get("limit") or ["200"])[0])))
            except ValueError: limit = 200
            task_id = str((query.get("taskId") or [""])[0])[:128]
            component = str((query.get("component") or [""])[0])[:64]
            clauses, params = ["id>?"], [after]
            if task_id: clauses.append("task_id=?"); params.append(task_id)
            if component: clauses.append("component=?"); params.append(component)
            params.append(limit)
            with db() as conn:
                rows = conn.execute("""SELECT id,occurred_at,received_at,component,category,operation,
                  process,parent_process,pid,ppid,resource,data,result,task_id,source,evidence
                  FROM agentsec_events WHERE """ + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ?", params).fetchall()
            keys = ["id","time","receivedAt","component","category","operation","process","parentProcess",
                    "pid","ppid","resource","data","result","taskId","source","evidence"]
            items = [dict(zip(keys, row)) for row in rows]
            payload = json.dumps({"events":items,"latestId":max([after]+[x["id"] for x in items]),
                                  "serverTime":datetime.now(timezone.utc).isoformat()}, ensure_ascii=False).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers(); self.wfile.write(payload); return
        if path in ("/download/apple-silicon", "/download/intel"):
            architecture = "Apple Silicon" if path.endswith("apple-silicon") else "Intel"
            query = urllib.parse.parse_qs(parsed.query)
            visitor_id, session_id = safe_id((query.get("vid") or [""])[0]), safe_id((query.get("sid") or [""])[0])
            ua = self.headers.get("user-agent", "")[:512]
            device, os_name, browser = classify(ua)
            ip = (self.headers.get("x-real-ip") or self.client_address[0])[:64]
            with db() as conn:
                conn.execute("DELETE FROM downloads WHERE occurred_at < ?", ((datetime.now(timezone.utc)-timedelta(days=30)).isoformat(),))
                conn.execute("INSERT INTO downloads(occurred_at,ip,architecture,referrer,user_agent,device,os,browser,visitor_id,session_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (datetime.now(timezone.utc).isoformat(), ip, architecture, self.headers.get("referer", "")[:1024], ua, device, os_name, browser, visitor_id, session_id))
            enrich_later(ip)
            filename = "AgentReins-Apple-Silicon.dmg" if architecture == "Apple Silicon" else "AgentReins-Intel.dmg"
            self.send_response(302); self.send_header("Location", f"/downloads/{filename}"); self.send_header("Cache-Control", "no-store"); self.end_headers(); return
        if path != "/api/admin/stats": return self.send_error(404)
        with db() as conn:
            visits = conn.execute("""SELECT v.occurred_at,v.ip,v.path,v.referrer,v.device,v.os,v.browser,v.user_agent,v.screen,v.language,v.visitor_id,v.session_id,
              g.country,g.region,g.city,g.asn,g.organization FROM visits v LEFT JOIN geo_cache g ON g.ip=v.ip ORDER BY v.id DESC LIMIT 500""").fetchall()
            downloads = conn.execute("""SELECT d.occurred_at,d.ip,d.architecture,d.referrer,d.device,d.os,d.browser,d.user_agent,d.visitor_id,d.session_id,
              g.country,g.region,g.city,g.asn,g.organization FROM downloads d LEFT JOIN geo_cache g ON g.ip=d.ip ORDER BY d.id DESC LIMIT 500""").fetchall()
            events = conn.execute("""SELECT occurred_at,ip,visitor_id,session_id,event_name,event_value,path,referrer,user_agent
              FROM behavior_events ORDER BY id DESC LIMIT 5000""").fetchall()
            summary = conn.execute("""SELECT
              (SELECT count(*) FROM visits),
              (SELECT count(DISTINCT ip) FROM (SELECT ip FROM visits UNION ALL SELECT ip FROM downloads)),
              (SELECT count(*) FROM downloads),
              (SELECT count(*) FROM downloads WHERE architecture='Apple Silicon'),
              (SELECT count(*) FROM downloads WHERE architecture='Intel')""").fetchone()
        visit_keys = ["time","ip","path","referrer","device","os","browser","userAgent","screen","language","visitorId","sessionId","country","region","city","asn","organization"]
        download_keys = ["time","ip","architecture","referrer","device","os","browser","userAgent","visitorId","sessionId","country","region","city","asn","organization"]
        visit_items = [dict(zip(visit_keys,row)) for row in visits]
        download_items = [dict(zip(download_keys,row)) for row in downloads]
        for item in visit_items + download_items:
            item["device"], item["os"], item["browser"] = classify(item.get("userAgent") or "")

        # A browser UA alone is not proof of a human. Preview services and security
        # scanners commonly run full Chrome on Linux, execute JavaScript, and fetch
        # every download link. Keep their evidence, but do not let it distort the
        # audience or conversion numbers.
        activity_by_ip = {}
        for item in visit_items + download_items:
            activity_by_ip.setdefault(item["ip"], []).append(item)
        automated_ips = set()
        cloud_pattern = re.compile(r"oracle|amazon|google|microsoft|azure|digitalocean|alibaba|tencent|ovh|hetzner", re.I)
        for ip, activity in activity_by_ip.items():
            unverified = all(not x.get("visitorId") for x in activity)
            organization = next((x.get("organization") or "" for x in activity if x.get("organization")), "")
            paths = {x.get("path") for x in activity if x.get("path")}
            architectures = {x.get("architecture") for x in activity if x.get("architecture")}
            times = []
            for item in activity:
                try: times.append(datetime.fromisoformat(item["time"]))
                except (TypeError, ValueError): pass
            burst = len(times) >= 4 and (max(times) - min(times)).total_seconds() <= 20
            fetched_every_build = {"Apple Silicon", "Intel"}.issubset(architectures)
            if unverified and (fetched_every_build or (cloud_pattern.search(organization) and burst and len(paths) >= 2)):
                automated_ips.add(ip)
        for item in visit_items:
            item["trafficClass"] = ("Bot" if item["device"] == "Bot / crawler" else
                                    "Likely automated / preview" if item["ip"] in automated_ips else
                                    "Human" if item.get("visitorId") else "Unverified / preview")
        for item in download_items:
            item["trafficClass"] = ("Bot" if item["device"] == "Bot / crawler" else
                                    "Likely automated / preview" if item["ip"] in automated_ips else
                                    "Human" if item.get("visitorId") else "Unverified / preview")
        event_keys = ["time","ip","visitorId","sessionId","name","value","path","referrer","userAgent"]
        event_items = [dict(zip(event_keys,row)) for row in events]
        human_visits = [x for x in visit_items if x["trafficClass"] in ("Human", "Unverified / preview")]
        human_downloads = [x for x in download_items if x["trafficClass"] in ("Human", "Unverified / preview")]
        identity = lambda x: x.get("visitorId") or x.get("ip")
        audience = {
          "humanVisitors": len({identity(x) for x in human_visits}),
          "verifiedVisitors": len({x["visitorId"] for x in human_visits if x.get("visitorId")}),
          "sessions": len({x.get("sessionId") or (x["ip"]+x["time"][:13]) for x in human_visits}),
          "qualifiedDownloads": len(human_downloads),
          "platforms": [], "countries": [], "sources": [], "events": []
        }
        def counts(values):
            result = {}
            for value in values: result[value or "Unknown"] = result.get(value or "Unknown", 0) + 1
            return [{"name":k,"count":v} for k,v in sorted(result.items(), key=lambda p:(-p[1],p[0]))]
        audience["platforms"] = counts(x["device"].split(" · ")[0] for x in human_visits)
        audience["countries"] = counts(x.get("country") for x in human_visits)
        audience["sources"] = counts((urllib.parse.urlsplit(x.get("referrer") or "").hostname or "Direct") for x in human_visits)
        audience["events"] = counts(x["name"] for x in event_items)
        session_events = {}
        for x in event_items:
            session_events.setdefault(x.get("sessionId") or "", set()).add(x["name"] + (":" + (x.get("value") or "")))
        audience["funnel"] = [
          {"name":"Sessions", "count":audience["sessions"]},
          {"name":"Engaged 30s", "count":sum(any(e.startswith("engaged_30s") for e in es) for es in session_events.values())},
          {"name":"Viewed product", "count":sum("section_view:product" in es for es in session_events.values())},
          {"name":"GitHub clicks", "count":sum("outbound_click:github" in es for es in session_events.values())},
          {"name":"Download intent", "count":sum("download_click:Apple Silicon" in es or "download_click:Intel" in es for es in session_events.values())},
          {"name":"Downloads", "count":len({x.get("sessionId") or x["ip"] for x in human_downloads})}
        ]
        data = json.dumps({"summary":dict(zip(["visits","uniqueIPs","downloads","appleSilicon","intel"],summary)),
                           "audience":audience, "visits":visit_items, "downloads":download_items}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/agentsec/ingest":
            supplied = self.headers.get("authorization", "")
            expected = "Bearer " + AGENTSEC_INGEST_TOKEN
            if not AGENTSEC_INGEST_TOKEN or not hmac.compare_digest(supplied, expected):
                self.send_error(401); return
            try:
                length = int(self.headers.get("content-length", "0"))
                if length < 2 or length > 1024 * 1024: raise ValueError("invalid body size")
                body = json.loads(self.rfile.read(length))
                events = body.get("events") if isinstance(body, dict) else None
                if not isinstance(events, list) or len(events) > 500: raise ValueError("invalid event batch")
                now = datetime.now(timezone.utc).isoformat()
                with db() as conn:
                    for event in events:
                        if not isinstance(event, dict): continue
                        evidence = json.dumps(event.get("evidence") or event, ensure_ascii=False, separators=(",", ":"))[:131072]
                        event_key = str(event.get("eventKey") or hashlib.sha256(evidence.encode()).hexdigest())[:128]
                        values = (event_key, str(event.get("time") or now)[:64], now,
                                  str(event.get("component") or "Unknown")[:64], str(event.get("category") or "runtime")[:32],
                                  str(event.get("operation") or "")[:64], str(event.get("process") or "")[:2048],
                                  str(event.get("parentProcess") or "")[:2048], int(event.get("pid") or 0), int(event.get("ppid") or 0),
                                  str(event.get("resource") or "")[:32768], str(event.get("data") or "")[:131072],
                                  str(event.get("result") or "")[:64], str(event.get("taskId") or "")[:128],
                                  str(event.get("source") or "")[:2048], evidence)
                        conn.execute("""INSERT OR IGNORE INTO agentsec_events(event_key,occurred_at,received_at,component,category,
                          operation,process,parent_process,pid,ppid,resource,data,result,task_id,source,evidence)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", values)
                    conn.execute("DELETE FROM agentsec_events WHERE received_at < ?", ((datetime.now(timezone.utc)-timedelta(days=30)).isoformat(),))
                self.send_response(202); self.end_headers()
            except (ValueError, TypeError, json.JSONDecodeError): self.send_error(400)
            return
        if path not in ("/api/visit", "/api/event"): return self.send_error(404)
        try:
            length = min(int(self.headers.get("content-length", "0")), 4096)
            body = json.loads(self.rfile.read(length) or b"{}")
            ua = self.headers.get("user-agent", "")[:512]
            device, os_name, browser = classify(ua)
            ip = (self.headers.get("x-real-ip") or self.client_address[0])[:64]
            visitor_id, session_id = safe_id(body.get("visitorId")), safe_id(body.get("sessionId"))
            with db() as conn:
                cutoff = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
                conn.execute("DELETE FROM visits WHERE occurred_at < ?", (cutoff,))
                conn.execute("DELETE FROM behavior_events WHERE occurred_at < ?", (cutoff,))
                if path == "/api/visit":
                    conn.execute("INSERT INTO visits(occurred_at,ip,path,referrer,user_agent,device,os,browser,screen,language,visitor_id,session_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (datetime.now(timezone.utc).isoformat(), ip, str(body.get("path","/"))[:512], str(body.get("referrer") or "")[:1024], ua, device, os_name, browser, str(body.get("screen") or "")[:32], str(body.get("language") or "")[:32], visitor_id, session_id))
                else:
                    event_name = str(body.get("name") or "")[:64]
                    if event_name:
                        conn.execute("INSERT INTO behavior_events(occurred_at,ip,visitor_id,session_id,event_name,event_value,path,referrer,user_agent) VALUES(?,?,?,?,?,?,?,?,?)",
                            (datetime.now(timezone.utc).isoformat(), ip, visitor_id, session_id, event_name, str(body.get("value") or "")[:256], str(body.get("path") or "/")[:512], str(body.get("referrer") or "")[:1024], ua))
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
