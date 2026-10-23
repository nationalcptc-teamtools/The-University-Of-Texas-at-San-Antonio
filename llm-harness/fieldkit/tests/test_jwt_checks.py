"""Independent JWT service fixtures, controls, private inputs and cryptographic bounds."""

import base64
import hmac
import io
import json
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from rich.console import Console

from fieldkit.core.jwt import JWTError, encode, load_key, modified, parse, serialize
from fieldkit.core.vault import Vault
from fieldkit.modules.jwt_check import JWTCheck, flatten_request, token_position

KEY = b"operator-only-signing-material-abcdefghijklmnopqrstuvwxyz-0123456789"
REAL_CLIENT = httpx.AsyncClient
ISSUER = "issuer-private-54321"
AUDIENCE = "client-private-45678"
SUBJECT = "alice-private-98765"
RESOURCE = "invoice-private-87654"
ADMIN = "admin-resource-private-76543"


def private_file(tmp_path, name, value):
    path = tmp_path / name
    path.write_bytes(value if isinstance(value, bytes) else value.encode())
    path.chmod(0o600)
    return str(path)


def private_json(tmp_path, name, value):
    return private_file(tmp_path, name, json.dumps(value))


def signed_token(claims=None, header=None):
    header = header or {"alg": "HS256", "typ": "JWT"}
    claims = claims or {
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "sub": SUBJECT,
        "exp": int(time.time()) + 3600,
        "role": "member-private-65432",
    }
    signing = serialize(header, claims)
    return signing + "." + encode(hmac.digest(KEY, signing.encode(), "sha256"))


def assertions(resource=RESOURCE):
    return {
        "status": 200,
        "identity": [{"pointer": "/user/id", "equals": SUBJECT}],
        "resource": [{"pointer": "/resource", "equals": resource}],
    }


def inputs(tmp_path, *, location="header:Authorization", profile=False):
    token = signed_token()
    request = {"id": "protected", "url": "https://jwt.test/protected", "method": "POST"}
    if location == "header:Authorization":
        request["headers"] = {"Authorization": "Bearer " + token}
    elif location == "header:X-JWT":
        request["headers"] = {"X-JWT": token}
    elif location == "cookie:session":
        request["cookies"] = {"session": token, "other": "preserved"}
    elif location == "form:credential":
        request["form"] = {"credential": token, "other": "preserved"}
    else:
        request["json"] = {"auth": {"credential": token}, "other": "preserved"}
    settings = {
        "REQUESTS_FILE": private_json(tmp_path, "requests.json", [request]),
        "REQUEST_IDS": ["protected"],
        "TOKEN_LOCATION": location,
        "KEY_FILE": private_file(tmp_path, "key.bin", KEY),
        "KEY_ALGORITHM": "HS256",
        "EXPECT_FILE": private_json(
            tmp_path,
            "expect.json",
            {
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "claims_policy": "deny",
                "baseline": assertions(),
                "probes": {"claims": assertions(ADMIN)},
            },
        ),
        "CLAIMS_FILE": private_json(tmp_path, "claims.json", {"role": "admin-private-32109"}),
        "ACTIVE": True,
        "CONFIRM_ACTIVE": True,
        "TARGETS": ["https://jwt.test"],
        "TESTS": ["signature", "none", "expired", "issuer", "audience", "claims"],
    }
    if profile:
        request.pop("headers", None)
        request["profile"] = "alice"
        settings["REQUESTS_FILE"] = private_json(tmp_path, "requests.json", [request])
        settings["PROFILES_FILE"] = private_json(
            tmp_path,
            "profiles.json",
            {
                "profiles": {
                    "alice": {
                        "origins": ["https://jwt.test"],
                        "headers": {"Authorization": "Bearer " + token},
                    }
                }
            },
        )
    return settings, token


def extract(request, location):
    if location == "header:Authorization":
        return request.headers.get("Authorization", "").removeprefix("Bearer ")
    if location == "header:X-JWT":
        return request.headers.get("X-JWT", "")
    if location == "cookie:session":
        cookie = SimpleCookie()
        cookie.load(request.headers.get("cookie", ""))
        return cookie["session"].value if "session" in cookie else ""
    if location == "form:credential":
        return parse_qs(request.content.decode()).get("credential", [""])[0]
    return json.loads(request.content).get("auth", {}).get("credential", "")


def service(*, weaknesses=(), location="header:Authorization", echo=False):
    """Validate independently of fieldkit's parser, signature verifier or policy checks."""

    def handler(request):
        compact = extract(request, location)
        try:
            encoded_header, encoded_claims, signature = compact.split(".")
            header, claims = [
                json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
                for part in (encoded_header, encoded_claims)
            ]
            signing = (encoded_header + "." + encoded_claims).encode()
            actual = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
            if header["alg"] == "none":
                if "none" not in weaknesses or signature:
                    raise ValueError
            elif header["alg"] != "HS256" or (
                "signature" not in weaknesses
                and not hmac.compare_digest(hmac.digest(KEY, signing, "sha256"), actual)
            ):
                raise ValueError
            if "expired" not in weaknesses and claims["exp"] <= time.time():
                raise ValueError
            if "issuer" not in weaknesses and claims["iss"] != ISSUER:
                raise ValueError
            if "audience" not in weaknesses and AUDIENCE not in claims["aud"]:
                raise ValueError
            resource = RESOURCE
            if claims["role"] == "admin-private-32109":
                if "claims" not in weaknesses:
                    raise ValueError
                resource = ADMIN
            body = {"user": {"id": claims["sub"]}, "resource": resource}
            if echo:
                body["echo"] = compact
                body["role"] = claims["role"]
            return httpx.Response(200, json=body, headers={"Set-Cookie": "sticky=private-session"})
        except (ValueError, KeyError, TypeError):
            return httpx.Response(401, json={"error": "invalid credential"})

    return handler


def run(tmp_path, monkeypatch, handler, **overrides):
    seen = []

    async def tracked(request):
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(
        "fieldkit.core.assessment.httpx.AsyncClient",
        lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(tracked), **kw),
    )
    settings = {**JWTCheck().defaults(), "OUTPUT": str(tmp_path / "runs"), "RATE": 0, **overrides}
    output = io.StringIO()
    code = JWTCheck().run(settings, Console(file=output))
    report_path = max((tmp_path / "runs").glob("*/report.json"), key=lambda p: p.stat().st_mtime_ns)
    return code, json.loads(report_path.read_text()), seen, report_path.parent, output.getvalue()


@pytest.mark.parametrize("weak", [False, True])
def test_all_selected_live_policies_safe_and_vulnerable(tmp_path, monkeypatch, weak):
    settings, token = inputs(tmp_path)
    code, report, seen, directory, output = run(
        tmp_path,
        monkeypatch,
        service(weaknesses=settings["TESTS"] if weak else [], echo=True),
        **settings,
    )
    assert code == 0 and len(seen) == 11
    assert {record["kind"] for record in report["findings"]} == (
        {"jwt_" + name for name in settings["TESTS"]} if weak else set()
    )
    outcomes = {item["outcome"] for item in report["results"][0]["tests"]}
    assert outcomes == ({"confirmed"} if weak else {"rejected"})
    # All controls/probes use explicit credentials, never session cookies set by earlier responses.
    assert all("sticky" not in request.headers.get("cookie", "") for request in seen)
    saved = output + "".join(path.read_text() for path in directory.rglob("*.json"))
    for secret in (
        token,
        KEY.decode(),
        ISSUER,
        AUDIENCE,
        SUBJECT,
        RESOURCE,
        ADMIN,
        "member-private-65432",
        "admin-private-32109",
    ):
        assert secret not in saved
    assert all(path.stat().st_mode & 0o077 == 0 for path in directory.rglob("*.json"))


@pytest.mark.parametrize(
    "location",
    [
        "header:Authorization",
        "header:X-JWT",
        "cookie:session",
        "form:credential",
        "json:/auth/credential",
    ],
)
def test_exact_wire_position_probes_and_missing_control(tmp_path, monkeypatch, location):
    settings, token = inputs(tmp_path, location=location)
    settings["TESTS"] = ["signature"]
    code, report, seen, _, _ = run(
        tmp_path,
        monkeypatch,
        service(weaknesses=["signature"], location=location),
        **settings,
    )
    assert code == 0 and len(seen) == 6 and len(report["findings"]) == 1
    assert extract(seen[0], location) == token
    assert extract(seen[2], location) == ""
    assert extract(seen[4], location) != token


def test_profile_selection_is_materialized_before_probe(tmp_path, monkeypatch):
    settings, token = inputs(tmp_path, profile=True)
    settings["TESTS"] = ["signature", "none"]
    _, report, seen, _, _ = run(
        tmp_path,
        monkeypatch,
        service(weaknesses=["signature", "none"]),
        **settings,
    )
    assert len(report["findings"]) == 2
    assert seen[0].headers["authorization"] == "Bearer " + token
    assert "authorization" not in seen[2].headers
    assert seen[4].headers["authorization"] != seen[0].headers["authorization"]


@pytest.mark.parametrize(
    "kind", ["public", "public-200", "login", "wrong-identity", "invalid-only"]
)
def test_public_pages_and_invalid_baselines_cannot_confirm(tmp_path, monkeypatch, kind):
    settings, token = inputs(tmp_path)
    settings["TESTS"] = ["signature", "none"]
    valid = service(weaknesses=["signature", "none"])

    def handler(request):
        if kind in {"public", "invalid-only"}:
            if (
                kind == "invalid-only"
                and extract(request, "header:Authorization") != "fieldkit-invalid-jwt"
            ):
                return valid(request)
            return httpx.Response(200, json={"user": {"id": SUBJECT}, "resource": RESOURCE})
        if kind == "public-200":
            return httpx.Response(200, json={"public": True})
        if kind == "login":
            return httpx.Response(200, text='<input type="password">')
        return httpx.Response(200, json={"user": {"id": "someone-else"}, "resource": RESOURCE})

    _, report, seen, _, _ = run(tmp_path, monkeypatch, handler, **settings)
    assert len(seen) == 4 and not report["findings"]
    assert report["results"][0]["outcome"] == "inconclusive"
    assert token not in json.dumps(report)


def test_final_baseline_must_still_prove_protection(tmp_path, monkeypatch):
    settings, _ = inputs(tmp_path)
    settings["TESTS"] = ["signature"]
    valid = service(weaknesses=["signature"])
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        return httpx.Response(403) if count == 6 else valid(request)

    _, report, seen, _, _ = run(tmp_path, monkeypatch, handler, **settings)
    assert len(seen) == 6 and not report["findings"]
    assert report["results"][0]["outcome"] == "inconclusive"


def test_signed_claim_acceptance_without_explicit_deny_policy_is_only_observed(
    tmp_path,
    monkeypatch,
):
    settings, _ = inputs(tmp_path)
    settings["TESTS"] = ["claims"]
    settings["EXPECT_FILE"] = private_json(
        tmp_path,
        "expect.json",
        {
            "baseline": assertions(),
            "probes": {"claims": assertions(ADMIN)},
        },
    )
    _, report, seen, _, _ = run(
        tmp_path,
        monkeypatch,
        service(weaknesses=["claims"]),
        **settings,
    )
    assert len(seen) == 6 and not report["findings"]
    assert report["results"][0]["outcome"] == "observed"
    assert report["results"][0]["tests"][0]["outcome"] == "accepted_signed_claims"


def test_expiration_probe_exceeds_ordinary_clock_skew(tmp_path, monkeypatch):
    settings, _ = inputs(tmp_path)
    settings["TESTS"] = ["expired"]
    valid = service()

    def handler(request):
        compact = extract(request, "header:Authorization")
        try:
            claims = parse(compact).claims
            if time.time() - 300 < claims["exp"] < time.time():
                return httpx.Response(200, json={"user": {"id": SUBJECT}, "resource": RESOURCE})
        except JWTError:
            pass
        return valid(request)

    _, report, seen, _, _ = run(tmp_path, monkeypatch, handler, **settings)
    assert len(seen) == 6 and not report["findings"]
    assert parse(extract(seen[4], "header:Authorization")).claims["exp"] < time.time() - 86000


def test_offline_and_dry_run_never_create_a_request(tmp_path, monkeypatch):
    token_file = private_file(tmp_path, "token.txt", signed_token())
    key_file = private_file(tmp_path, "key.bin", KEY)
    code, report, seen, _, _ = run(
        tmp_path,
        monkeypatch,
        lambda request: pytest.fail("offline HTTP"),
        TOKEN_FILE=token_file,
        KEY_FILE=key_file,
        KEY_ALGORITHM="HS256",
    )
    assert code == 0 and not seen and report["results"][0]["signature"] == "verified"
    assert report["results"][0]["mode"] == "offline"
    settings, _ = inputs(tmp_path)
    settings.update(DRY_RUN=True, CONFIRM_ACTIVE=False)
    code, report, seen, _, _ = run(
        tmp_path,
        monkeypatch,
        lambda request: pytest.fail("dry-run HTTP"),
        **settings,
    )
    assert code == 0 and not seen and report["plan"]["network_requests"] == 0


@pytest.mark.parametrize(
    "overrides,diagnostic",
    [
        ({"CONFIRM_ACTIVE": False}, "CONFIRM_ACTIVE"),
        ({"TARGETS": []}, "explicit origins"),
        ({"TARGETS": ["jwt.test"]}, "explicit HTTP"),
        ({"TARGETS": ["https://outside.test"]}, "scope"),
        ({"TESTS": []}, "TESTS"),
        ({"TESTS": ["bruteforce"]}, "unsupported"),
        ({"MAX_REQUESTS": 10}, "MAX_REQUESTS"),
        ({"MAX_TOKEN_BYTES": 0}, "MAX_TOKEN_BYTES"),
        ({"MAX_TOKEN_BYTES": 65537}, "MAX_TOKEN_BYTES"),
        ({"RETRIES": 1}, "RETRIES"),
        ({"REQUEST_IDS": []}, "selection"),
        ({"KEY_FILE": ""}, "KEY_ALGORITHM"),
    ],
)
def test_live_rejects_unbounded_or_unselected_inputs_before_http(
    tmp_path,
    monkeypatch,
    overrides,
    diagnostic,
):
    settings, _ = inputs(tmp_path)
    settings.update(overrides)
    with pytest.raises(ValueError, match=diagnostic):
        run(tmp_path, monkeypatch, lambda request: pytest.fail("invalid plan HTTP"), **settings)


def test_status_only_and_reflected_claim_outcomes_are_not_assertions(tmp_path, monkeypatch):
    settings, _ = inputs(tmp_path)
    settings["EXPECT_FILE"] = private_json(tmp_path, "expect.json", {"baseline": {"status": 200}})
    with pytest.raises(JWTError, match="identity or resource"):
        run(tmp_path, monkeypatch, lambda request: pytest.fail("invalid plan HTTP"), **settings)
    settings["EXPECT_FILE"] = private_json(
        tmp_path,
        "expect.json",
        {"baseline": assertions(), "probes": {"claims": assertions()}},
    )
    settings["TESTS"] = ["claims"]
    with pytest.raises(JWTError, match="differ"):
        run(tmp_path, monkeypatch, lambda request: pytest.fail("invalid plan HTTP"), **settings)


def test_raw_and_vault_selection(tmp_path, monkeypatch):
    settings, token = inputs(tmp_path)
    settings["TESTS"] = ["none"]
    settings["REQUESTS_FILE"] = private_file(
        tmp_path,
        "request.http",
        "GET /protected HTTP/1.1\r\nHost: jwt.test\r\nAuthorization: Bearer " + token + "\r\n\r\n",
    )
    settings.update(RAW=True, RAW_URL="https://jwt.test", REQUEST_IDS=["1"])
    _, report, seen, _, _ = run(tmp_path, monkeypatch, service(weaknesses=["none"]), **settings)
    assert len(seen) == 6 and len(report["findings"]) == 1
    with Vault(tmp_path / "private.sqlite") as vault:
        request_id = vault.exchange(
            {
                "url": "https://jwt.test/protected",
                "headers": {"Authorization": "Bearer " + token},
            }
        )
    settings.update(
        REQUESTS_FILE="",
        RAW=False,
        DATABASE=str(tmp_path / "private.sqlite"),
        REQUEST_IDS=[request_id],
    )
    _, report, seen, _, _ = run(tmp_path, monkeypatch, service(weaknesses=["none"]), **settings)
    assert len(seen) == 6 and len(report["findings"]) == 1
    assert report["results"][0]["request_id"] == request_id


def test_token_key_and_claim_inputs_are_private_regular_bounded_files(tmp_path):
    token = private_file(tmp_path, "token.txt", signed_token())
    module = JWTCheck()
    settings = {**module.defaults(), "TOKEN_FILE": token}
    (tmp_path / "token.txt").chmod(0o644)
    with pytest.raises(JWTError, match="owner-only"):
        module.validate(settings)
    (tmp_path / "token.txt").chmod(0o600)
    (tmp_path / "link.txt").symlink_to(tmp_path / "token.txt")
    with pytest.raises(JWTError, match="safely read"):
        module.validate({**settings, "TOKEN_FILE": str(tmp_path / "link.txt")})
    with pytest.raises(JWTError, match="byte limit"):
        module.validate({**settings, "MAX_TOKEN_BYTES": 4})
    claims = private_file(tmp_path, "claims.json", '{"role":"one","role":"two"}')
    with pytest.raises(JWTError, match="Malformed JWT JSON"):
        module.validate({**settings, "CLAIMS_FILE": claims})
    key = private_file(tmp_path, "weak.key", b"weak")
    verification = load_key(key, "HS256")
    signing = serialize({"alg": "HS256"}, {"sub": SUBJECT})
    compact = signing + "." + encode(hmac.digest(b"weak", signing.encode(), "sha256"))
    assert verification.verify(parse(compact)) == "verified"
    assert verification.strength == "below_recommended"
    key = private_file(tmp_path, "empty.key", b"")
    with pytest.raises(JWTError, match="nonempty"):
        load_key(key, "HS256")


@pytest.mark.parametrize(
    "algorithm,key",
    [
        ("RS256", lambda: rsa.generate_private_key(public_exponent=65537, key_size=1024)),
        ("RS256", lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("PS256", lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("ES256", lambda: ec.generate_private_key(ec.SECP256R1())),
        ("ES384", lambda: ec.generate_private_key(ec.SECP384R1())),
        ("ES512", lambda: ec.generate_private_key(ec.SECP521R1())),
        ("EdDSA", ed25519.Ed25519PrivateKey.generate),
    ],
)
def test_asymmetric_operator_keys_verify_and_sign_without_algorithm_confusion(
    tmp_path,
    algorithm,
    key,
):
    private = key()
    private_path = private_file(
        tmp_path,
        "private.pem",
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    public_path = private_file(
        tmp_path,
        "public.pem",
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    signer, verifier = load_key(private_path, algorithm), load_key(public_path, algorithm)
    compact = signer.sign({"alg": algorithm}, {"sub": SUBJECT})
    token = parse(compact)
    assert signer.can_sign and not verifier.can_sign
    assert verifier.verify(token) == "verified"
    assert verifier.verify(parse(modified(token, claims={"sub": "changed"}))) == "invalid"
    with pytest.raises(JWTError, match="PEM is forbidden"):
        load_key(public_path, "HS256")
    with pytest.raises(JWTError, match="signing key"):
        verifier.sign({"alg": algorithm}, {"sub": SUBJECT})


@pytest.mark.parametrize(
    "header,claims",
    [
        ({"alg": "HS256", "b64": False}, {}),
        ({"alg": "HS256", "crit": ["jku"]}, {}),
        ({"alg": "HS256"}, {"exp": True}),
        ({"alg": "HS256"}, {"exp": None}),
        ({"alg": "HS256"}, {"exp": 10**500}),
        ({"alg": "HS256"}, {"iss": []}),
        ({"alg": "HS256"}, {"aud": [1]}),
    ],
)
def test_parser_rejects_unsupported_and_malformed_claim_schema(header, claims):
    with pytest.raises(JWTError):
        parse(serialize(header, claims) + ".")


def test_metadata_never_fetches_remote_key_urls_and_wrong_alg_does_not_verify(
    tmp_path, monkeypatch
):
    token = signed_token(
        header={"alg": "HS256", "jku": "https://outside.test/key", "kid": "private-kid"}
    )
    path = private_file(tmp_path, "token.txt", token)
    _, report, seen, _, _ = run(
        tmp_path,
        monkeypatch,
        lambda request: pytest.fail("remote key fetch"),
        TOKEN_FILE=path,
        KEY_FILE=private_file(tmp_path, "key.bin", KEY),
        KEY_ALGORITHM="HS384",
    )
    assert not seen
    result = report["results"][0]
    assert result["signature"] == "algorithm_mismatch"
    assert result["token"]["remote_key_reference_ignored"] is True
    assert "outside.test" not in json.dumps(report) and "private-kid" not in json.dumps(report)


def test_cookie_and_pointer_ambiguity_rejected():
    request = {"url": "https://jwt.test/", "headers": {"Cookie": "session=a; session=b"}}
    with pytest.raises(JWTError, match="ambiguous"):
        token_position(request, "cookie:session")
    request = {"url": "https://jwt.test/", "json": {"a": {"~2": "value"}}}
    with pytest.raises(JWTError, match="RFC 6901"):
        token_position(request, "json:/a/~2")


def test_cookie_profile_path_scope_is_preserved():
    from fieldkit.core.profiles import SessionProfile

    profiles = {
        "alice": SessionProfile(
            "alice",
            ["https://jwt.test"],
            {},
            {},
            [
                {
                    "name": "session",
                    "value": signed_token(),
                    "domain": "jwt.test",
                    "path": "/admin",
                },
            ],
        )
    }
    request = flatten_request({"url": "https://jwt.test/public"}, profiles, "alice")
    assert "cookie" not in request["headers"]
    request = flatten_request({"url": "https://jwt.test/admin/page"}, profiles, "alice")
    assert "session=" in request["headers"]["cookie"]
