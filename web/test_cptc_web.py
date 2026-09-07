"""Synthetic loopback integration and regression tests. No external targets."""
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import cptc_web as w


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, code, body, cookie=None):
        body = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/html")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if self.server.mode == "redirect":
            self.send_header("Location", "http://192.0.2.42/outside")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.seen.append(("GET", self.path))
        mode = self.server.mode
        if mode == "redirect":
            return self.respond(302, "go elsewhere")
        if mode == "throttle":
            return self.respond(429, "slow down")
        if self.path == "/" and mode == "grafana_root_redirect":
            return self.respond(302, "login required")
        if self.path in ("/", "/login"):
            if mode == "truncated_login" and self.path == "/login":
                return self.respond(200, '<title>Grafana</title><script src="public/build/app.js"></script>' + 'A' * w.MAX_BODY)
            return self.respond(200, '<title>Grafana</title><script src="public/build/app.js"></script>')
        if self.path == "/api/health":
            return self.respond(200, {"database": "ok", "version": "test-fixture"})
        if self.path == "/api/user":
            session = self.headers.get("Cookie", "") == "grafana_session=fixture-session-secret"
            if mode == "public_identity" or (session and mode != "fake_cookie"):
                return self.respond(200, {"id": 1, "login": "other" if mode == "wrong_identity" else "admin", "isGrafanaAdmin": True})
            return self.respond(401, {"message": "Unauthorized"})
        if mode == "catchall" or (self.path == "/.git/HEAD" and mode == "vulnerable"):
            return self.respond(200, "ref: refs/heads/main\n")
        if mode == "large":
            return self.respond(200, "A" * (w.MAX_BODY + 500))
        return self.respond(404, "missing")

    def do_POST(self):
        self.server.seen.append(("POST", self.path))
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.posts.append(data)
        good = data == {"user": "admin", "password": "admin"}
        if self.server.mode == "any_login":
            return self.respond(200, {"message": "ok"}, "grafana_session=fixture-session-secret; HttpOnly")
        if self.server.mode == "login_throttle":
            return self.respond(429, {"message": "slow down"})
        if self.server.mode == "negative_cookie" and not good:
            return self.respond(401, {"message": "invalid"}, "grafana_session=fixture-session-secret")
        if self.server.mode == "login_forbidden" and good:
            return self.respond(403, {"message": "blocked by policy"})
        if not good or self.server.mode == "hardened":
            return self.respond(401, {"message": "invalid"})
        return self.respond(200, {"message": "ok"}, "grafana_session=fixture-session-secret; HttpOnly")


@contextlib.contextmanager
def server(mode="vulnerable"):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    srv.mode, srv.seen, srv.posts = mode, [], []
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv, f"http://127.0.0.1:{srv.server_port}/"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join()


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "run"
        self.scope = w.Scope({"allowed_cidrs": ["127.0.0.0/8"], "allowed_hosts": ["localhost"], "allow_http_login": True})
        with w.engagement(self.root, self.scope):
            pass

    def tearDown(self):
        self.tmp.cleanup()

    def result(self, db, app, key):
        return dict(db.execute("SELECT * FROM checks WHERE app=? AND id=?", (app, key)).fetchone())

    def test_canonical_distinct_apps_ipv6_and_ports(self):
        self.assertEqual(w.canonical_url("https://Example.com:443/grafana"), "https://example.com/grafana/")
        self.assertEqual(w.canonical_url("http://[::1]:8080/"), "http://[::1]:8080/")
        with w.engagement(self.root) as (_, db, scope):
            ids = [w.add_app(db, scope, u, "web") for u in ["http://127.0.0.1", "http://127.0.0.1/", "http://127.0.0.1/a/", "http://127.0.0.1:8080"]]
            self.assertEqual(ids[0], ids[1]); self.assertEqual(len(set(ids)), 3)

    def test_reject_ambiguous_urls(self):
        for url in ["file:///etc/passwd", "http://a:b@localhost", "http://localhost/?token=foo", "http://localhost/#x", "http://localhost/a/../b", "http://localhost/%2e%2e/", "http://localhost/a\\b", "http://localhost:0/", "http://localhost/a\n", "http://localhost//a"]:
            with self.subTest(url=url), self.assertRaises(w.WorkflowError):
                w.canonical_url(url)

    def test_exclusions_win_and_hosts_explicit(self):
        scope = w.Scope({"allowed_cidrs": ["127.0.0.0/8"], "excluded_cidrs": ["127.0.0.2/32"]})
        for url in ["http://127.0.0.2", "http://192.0.2.1", "http://localhost"]:
            with self.assertRaises(w.WorkflowError): scope.check_url(url)

    def test_mapped_ipv6_cannot_bypass_exclusion(self):
        scope = w.Scope({"allowed_cidrs": ["127.0.0.0/8", "::/0"], "excluded_cidrs": ["127.0.0.2/32"]})
        self.assertFalse(scope.ip_allowed("::ffff:127.0.0.2"))

    def test_mixed_dns_answers_refused_before_connect(self):
        answers = [(2, 1, 6, "", ("127.0.0.1", 80)), (2, 1, 6, "", ("192.0.2.1", 80))]
        with patch.object(w.socket, "getaddrinfo", return_value=answers), patch.object(w.socket.socket, "connect") as connect:
            with self.assertRaises(w.WorkflowError): w.HTTP(self.scope, "http://localhost/").request()
            connect.assert_not_called()

    def test_valid_dns_is_pinned_to_numeric_address(self):
        with server() as (srv, _):
            answers = [(2, 1, 6, "", ("127.0.0.1", srv.server_port))]
            with patch.object(w.socket, "getaddrinfo", return_value=answers) as resolve:
                response = w.HTTP(self.scope, f"http://localhost:{srv.server_port}/", delay=0).request()
                self.assertEqual(response["status"], 200)
                self.assertEqual(resolve.call_count, 1)

    def test_redirect_is_never_followed(self):
        with server("redirect") as (srv, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertFalse(w.scan(db, scope, app, delay=0))
            self.assertEqual(len(srv.seen), 1)
            self.assertEqual(self.result(db, app, "http_baseline")["state"], "blocked")

    def test_basic_scan_finds_git_and_preserves_manual_auth_checks(self):
        with server() as (_, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertTrue(w.scan(db, scope, app, delay=0))
            self.assertEqual(self.result(db, app, "git_metadata")["result"], "candidate")
            for key in ["default_credentials", "authorization", "login_surface", "app_map"]:
                self.assertEqual(self.result(db, app, key)["state"], "pending")

    def test_catchall_200_is_not_git_exposure(self):
        with server("catchall") as (_, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            w.scan(db, scope, app, delay=0)
            self.assertEqual(self.result(db, app, "git_metadata")["result"], "no_issue_observed")

    def test_scan_throttle_stops_immediately(self):
        with server("throttle") as (srv, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertFalse(w.scan(db, scope, app, delay=0)); self.assertEqual(len(srv.seen), 1)
            check = self.result(db, app, "http_baseline")
            refs = json.loads(check["evidence"])
            evidence = json.loads(db.execute("SELECT data FROM evidence WHERE id=?", (refs[0],)).fetchone()[0])
            self.assertEqual(evidence["status"], 429)
            self.assertEqual(evidence["resolved_ip"], "127.0.0.1")
            self.assertEqual(evidence["method"], "GET")

    def test_body_cap(self):
        with server("large") as (_, url):
            response = w.HTTP(self.scope, url, delay=0).request("large")
            self.assertEqual(len(response["body"]), w.MAX_BODY)
            self.assertTrue(response["evidence"]["truncated"])

    def test_request_budget_and_path_checks(self):
        with server() as (_, url):
            client = w.HTTP(self.scope, url, limit=1, delay=0)
            client.request()
            with self.assertRaises(w.WorkflowError): client.request()
            for path in ["/elsewhere", "../escape", "http://outside/", "api?x=y"]:
                with self.assertRaises(w.WorkflowError): w.HTTP(self.scope, url).request(path)

    def test_grafana_verified_and_no_session_in_exports(self):
        with server() as (srv, url), w.engagement(self.root) as (root, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertTrue(w.default_credentials(db, scope, app, delay=0))
            self.assertEqual(self.result(db, app, "default_credentials")["result"], "confirmed")
            self.assertEqual(len(srv.posts), 2)
            out = w.export(root, db)
            for path in out.iterdir():
                self.assertNotIn("fixture-session-secret", path.read_text())
                self.assertNotIn('"password":', path.read_text())
            self.assertIn("Business impact: requires", (out / f"app-{app}.md").read_text())

    def test_grafana_hardened(self):
        with server("hardened") as (_, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertTrue(w.default_credentials(db, scope, app, delay=0))
            self.assertEqual(self.result(db, app, "default_credentials")["result"], "no_issue_observed")

    def test_grafana_login_page_works_with_root_redirect(self):
        with server("grafana_root_redirect") as (srv, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertTrue(w.default_credentials(db, scope, app, delay=0))
            self.assertNotIn(("GET", "/"), srv.seen)
            self.assertEqual(self.result(db, app, "default_credentials")["result"], "confirmed")

    def test_truncated_login_page_blocks_before_credentials(self):
        with server("truncated_login") as (srv, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertFalse(w.default_credentials(db, scope, app, delay=0))
            self.assertEqual(srv.posts, [])
            self.assertEqual(self.result(db, app, "default_credentials")["state"], "blocked")

    def test_login_throttle_preserves_response_evidence(self):
        with server("login_throttle") as (_, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertFalse(w.default_credentials(db, scope, app, delay=0))
            item = db.execute("SELECT data FROM evidence WHERE app=?", (app,)).fetchone()[0]
            response = json.loads(item)["responses"][-1]
            self.assertEqual(response["status"], 429)
            self.assertEqual(response["method"], "POST")
            self.assertEqual(response["resolved_ip"], "127.0.0.1")

    def test_false_auth_success_cases_remain_blocked(self):
        for mode in ["public_identity", "any_login", "fake_cookie", "wrong_identity", "login_throttle", "negative_cookie", "login_forbidden"]:
            with self.subTest(mode=mode), server(mode) as (srv, url), w.engagement(self.root) as (_, db, scope):
                app = w.add_app(db, scope, url, "web")
                self.assertFalse(w.default_credentials(db, scope, app, delay=0))
                self.assertEqual(self.result(db, app, "default_credentials")["state"], "blocked")
                if mode in ("public_identity", "any_login", "login_throttle", "negative_cookie"):
                    self.assertLessEqual(len(srv.posts), 1)

    def test_login_budget_persists_across_invocations(self):
        with server() as (srv, url):
            with w.engagement(self.root) as (_, db, scope):
                app = w.add_app(db, scope, url, "web")
                w.default_credentials(db, scope, app, delay=0)
            with w.engagement(self.root) as (_, db, scope):
                self.assertFalse(w.default_credentials(db, scope, app, delay=0))
                self.assertEqual(len(srv.posts), 2)
                self.assertEqual(self.result(db, app, "default_credentials")["result"], "confirmed")
                last = db.execute("SELECT state FROM events ORDER BY id DESC").fetchone()[0]
                self.assertEqual(last, "blocked")

    def test_http_login_requires_scope_opt_in(self):
        with server() as (srv, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            scope.http_login = False
            self.assertFalse(w.default_credentials(db, scope, app, delay=0))
            self.assertEqual(srv.seen, [])

    def test_unknown_product_never_gets_credentials(self):
        with server("redirect") as (srv, url), w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, url, "web")
            self.assertFalse(w.default_credentials(db, scope, app, delay=0))
            self.assertEqual(srv.posts, [])

    def test_manual_complete_requires_evidence_and_result(self):
        with w.engagement(self.root) as (_, db, scope):
            app = w.add_app(db, scope, "http://127.0.0.1", "web")
            for state, result, note in [("complete", "confirmed", "proof"), ("blocked", "confirmed", "no proof"), ("na", "not_tested", "")]:
                with self.assertRaises(w.WorkflowError): w.record(db, app, "authorization", state, result, note)

    def test_evidence_attribution_and_history(self):
        with w.engagement(self.root) as (_, db, scope):
            first = w.add_app(db, scope, "http://127.0.0.1/a", "web")
            second = w.add_app(db, scope, "http://127.0.0.1/b", "web")
            eid = w.save_evidence(db, first, "authorization", {"source": "fixture"})
            with self.assertRaises(w.WorkflowError): w.record(db, second, "authorization", "complete", "confirmed", "proof", [eid])
            w.record(db, first, "authorization", "complete", "confirmed", "proof", [eid])
            w.record(db, first, "authorization", "complete", "no_issue_observed", "retest", [eid], automatic=True)
            self.assertEqual(self.result(db, first, "authorization")["result"], "confirmed")
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 2)

    def test_artifacts_must_be_inside_engagement(self):
        external = Path(self.tmp.name) / "outside.txt"; external.write_text("fixture")
        with self.assertRaises(w.WorkflowError): w.evidence_file(self.root, external)
        target = self.root / "evidence" / "proof.txt"; target.write_text("fixture")
        proof = w.evidence_file(self.root, target)
        self.assertEqual(proof["sha256"], w.digest(b"fixture"))
        link = self.root / "evidence" / "link"; link.symlink_to(external)
        with self.assertRaises(w.WorkflowError): w.evidence_file(self.root, link)

    def test_nmap_import_handles_tls_ipv6_duplicates_and_exclusions(self):
        scope = w.Scope({"allowed_cidrs": ["127.0.0.0/8", "::1/128"]})
        xml = '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><address addr="::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="9443"><state state="open"/><service name="http" tunnel="ssl"/></port><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>'
        path = Path(self.tmp.name) / "scan.xml"; path.write_text(xml)
        with w.engagement(self.root) as (_, db, _):
            self.assertEqual(w.import_nmap(db, scope, path, "web"), (2, 1))
            self.assertEqual(w.import_nmap(db, scope, path, "web"), (2, 1))
            self.assertEqual(db.execute("SELECT count(*) FROM apps").fetchone()[0], 2)
            self.assertTrue(all(r[0].startswith("https://") for r in db.execute("SELECT url FROM apps")))

    def test_bad_xml_and_entities_refused(self):
        path = Path(self.tmp.name) / "bad.xml"
        with w.engagement(self.root) as (_, db, scope):
            for xml in ["<broken", "<other/>", '<!DOCTYPE nmaprun [<!ENTITY x "secret">]><nmaprun/>']:
                path.write_text(xml)
                with self.assertRaises(w.WorkflowError): w.import_nmap(db, scope, path, "web")

    def test_concurrent_command_refused(self):
        with w.engagement(self.root):
            with self.assertRaises(w.WorkflowError):
                with w.engagement(self.root): pass

    def test_export_symlink_refused(self):
        target = Path(self.tmp.name) / "other"; target.mkdir()
        (self.root / "export").symlink_to(target, target_is_directory=True)
        with w.engagement(self.root) as (root, db, _):
            with self.assertRaises(w.WorkflowError): w.export(root, db)

    def test_changed_artifact_blocks_export(self):
        with w.engagement(self.root) as (root, db, scope):
            app = w.add_app(db, scope, "http://127.0.0.1/", "web")
            proof = root / "evidence" / "proof.md"; proof.write_text("original")
            eid = w.save_evidence(db, app, "inventory", w.evidence_file(root, proof))
            w.record(db, app, "inventory", "complete", "observed", "Reviewed", [eid])
            proof.write_text("changed")
            with self.assertRaises(w.WorkflowError): w.export(root, db)

    def test_invalid_scope_shape(self):
        for data in [{}, {"allowed_cidrs": "127.0.0.0/8"}, {"allowed_cidrs": ["127.0.0.0/8"], "allow_http_login": "false"}, {"allowed_cidrs": ["127.0.0.0/8"], "allowed_hosts": ["*.test"]}]:
            with self.assertRaises(w.WorkflowError): w.Scope(data)

    def test_notes_redact_json_and_entire_authorization_values(self):
        values = ["sentinel-json-pass", "sentinel-json-token", "sentinel-cookie", "sentinel-bearer", "sentinel-header-cookie"]
        note = '{"password":"'+values[0]+'","token":"'+values[1]+'","cookie":"'+values[2]+'"}\nAuthorization: Bearer '+values[3]+'\nCookie: sid='+values[4]+'; other=x'
        with w.engagement(self.root) as (root, db, scope):
            app = w.add_app(db, scope, "http://127.0.0.1/", "web")
            w.record(db, app, "authorization", "blocked", "not_tested", note)
            out = w.export(root, db)
            for path in out.iterdir():
                for value in values:
                    self.assertNotIn(value, path.read_text())

    def test_nmap_provenance_preserves_locator_and_metadata_without_args(self):
        path = Path(self.tmp.name) / "fixture-scan.xml"
        raw = '<nmaprun scanner="nmap" version="7.95" start="1234" args="nmap --script-args password=sentinel-import"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
        path.write_text(raw)
        with w.engagement(self.root) as (_, db, scope):
            w.import_nmap(db, scope, path, "web")
            serialized = db.execute("SELECT data FROM evidence").fetchone()[0]
            data = json.loads(serialized)
            self.assertEqual(data["source_file"], "fixture-scan.xml")
            self.assertEqual(data["scanner"], "nmap")
            self.assertEqual(data["scanner_version"], "7.95")
            self.assertEqual(data["source_sha256"], w.digest(raw.encode()))
            self.assertNotIn("sentinel-import", serialized)

    def test_cli_batch_scan_and_assignment(self):
        with server() as (_, url), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(w.main(["add", str(self.root), url, "--owner", "first"]), 0)
            self.assertEqual(w.main(["assign", str(self.root), "1", "second"]), 0)
            self.assertEqual(w.main(["scan", str(self.root), "--all"]), 0)
            with w.engagement(self.root) as (_, db, _):
                self.assertEqual(w.app_row(db, 1)["owner"], "second")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(w.main(["scan", str(self.root)]), 2)
            self.assertEqual(w.main(["scan", str(self.root), "1", "--all"]), 2)

    def test_cli_end_to_end(self):
        with server("hardened") as (_, url), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(w.main(["add", str(self.root), url, "--owner", "web"]), 0)
            self.assertEqual(w.main(["scan", str(self.root), "1"]), 0)
            self.assertEqual(w.main(["default-creds", str(self.root), "1"]), 0)
            proof = self.root / "evidence" / "manual.txt"; proof.write_text("Synthetic review of inventory")
            self.assertEqual(w.main(["record", str(self.root), "1", "inventory", "--state", "complete", "--result", "observed", "--note", "Reviewed inventory", "--evidence", str(proof)]), 0)
            self.assertEqual(w.main(["export", str(self.root)]), 0)
            self.assertEqual(w.main(["status", str(self.root)]), 0)
            data = json.loads((self.root / "export" / "evidence.json").read_text())
            self.assertTrue(data["next_actions"])
            self.assertTrue(data["apps"][0]["history"])


if __name__ == "__main__":
    unittest.main()
