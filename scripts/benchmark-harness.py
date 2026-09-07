#!/usr/bin/env python3
"""Offline synthetic token comparison. --prepare downloads only the pinned public tokenizer."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".tools/benchmark"))
from cptc_harness.audit import AuditWriter
from cptc_harness.contracts import AuditEvent, PolicySnapshot, ScopeSpec
from cptc_harness.orchestrator import rules_reference
from cptc_harness.preambles import build_preamble
from cptc_harness.registry import build_registry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import tiktoken
    if tiktoken.__version__ != "0.12.0":
        parser.error("benchmark requires pinned tiktoken==0.12.0")
    cache = ROOT / ".tools/tokenizer-cache"
    url = "https://openaipublic.blob.core.windows.net/encodings/o200k_base.tiktoken"
    encoded_file = cache / hashlib.sha1(url.encode()).hexdigest()
    expected = "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"
    if not args.prepare and (not encoded_file.is_file() or hashlib.sha256(encoded_file.read_bytes()).hexdigest() != expected):
        parser.error("prepare the pinned public tokenizer once before offline benchmarking")
    os.environ["TIKTOKEN_CACHE_DIR"] = str(cache)
    encoding = tiktoken.get_encoding("o200k_base")
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    policy = PolicySnapshot("synthetic-benchmark", "v1", "benchmark", "fixture", "operator", ScopeSpec())
    prompt = build_preamble(policy, rules_reference(), (build_registry().get("web.headers"),)).text
    transcript, compact, baseline = [], [], []
    audit = AuditWriter(args.output / "audit", policy)
    try:
        for i in range(24):
            raw = f"synthetic request {i + 1}: GET /fixture/{i + 1}\nstatus: 200\nheaders: content-type=text/html; x-frame-options=DENY\n" + (f"Synthetic fixture line {i + 1}. No client data. " * 40)
            audit.emit(AuditEvent("synthetic_process_start", str(i + 1), {"command": ["fixture", str(i + 1)]}))
            audit.capture(str(i + 1), "stdout", raw.encode(), "synthetic")
            audit.emit(AuditEvent("synthetic_process_complete", str(i + 1), {"exit_code": 0, "bytes": len(raw.encode())}))
            transcript.append(raw)
            if (i + 1) % 4 == 0:
                baseline.append(prompt + "\n" + "\n".join(transcript))
                compact.append(prompt + "\n" + json.dumps({"completed": i + 1, "status": "observed", "changed": list(range(i - 2, i + 2)), "http_status": 200, "header_present": True}, separators=(",", ":")))
        full = "\n".join(transcript).encode()
        before = sum(len(encoding.encode(x)) for x in baseline)
        after = sum(len(encoding.encode(x)) for x in compact)
        result = {"classification": "synthetic", "tokenizer": "tiktoken 0.12.0 / o200k_base", "baseline_version": "24-observations-6-turns-v1",
                  "input_tokens_baseline": before, "input_tokens_compact": after, "input_token_reduction_percent": round(100 * (before - after) / before, 2),
                  "comparison": "Same compact preamble on all six turns; accumulated raw transcript versus typed state changes.",
                  "actual_model_calls": 0, "network_target_requests": 0, "synthetic_stdout_bytes_retained": sum(len(x.encode()) for x in transcript),
                  "fixture_sha256": hashlib.sha256(full).hexdigest(), "audit_verified": audit.verify().valid,
                  "limitations": "Input-token fixture comparison only; no claim about actual provider tokenizer, billing, output tokens, or reasoning usage."}
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    finally:
        audit.close()


if __name__ == "__main__":
    main()
