import copy
import importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location("external_benchmark", Path(__file__).parents[1]/"testing/benchmark.py")
benchmark=importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def inputs():
    entry={"issue_id":"i1", "population":"original_scenario", "eligibility":"automated",
           "target":"blinded-host", "rule_id":"rule", "role_id":"reader", "cve_ids":["CVE-2021-41773"],
           "required_evidence_fields":["version", "configuration"], "source_sha256":"a"*64, "expectation":"present"}
    catalog={"schema":benchmark.SCHEMA, "catalog_id":"independent", "reviewer":"human",
             "scope_sha256":"b"*64, "provenance_sha256":"c"*64, "catalog_complete":True, "entries":[entry]}
    row={"target":"blinded-host", "rule_id":"rule", "role_id":"reader", "cve_ids":["CVE-2021-41773"],
         "disposition":"observed_condition", "collection_complete":True, "source_actions":["action"],
         "evidence_ids":["artifact"], "evidence_fields":["version", "configuration"], "limitations":[]}
    return catalog, {"scope_sha256":"b"*64,"provenance_sha256":"c"*64,
        "evidence_index":[{"evidence_id":"artifact","sha256":"d"*64,"source_action":"action"}],"detections":[row]}


def test_exact_evidence_match_and_no_runtime_mutation():
    catalog, report=inputs(); before=copy.deepcopy(report)
    assert benchmark.score_benchmark(catalog,report)["complete"]
    catalog["entries"][0]["target"]="withheld-host"
    result=benchmark.score_benchmark(catalog,report)
    assert not result["complete"] and result["results"][0]["status"]=="missed"
    assert report==before


@pytest.mark.parametrize("change", [{"disposition":"candidate"}, {"collection_complete":False},
    {"source_actions":[]}, {"evidence_ids":[]}, {"evidence_fields":["version"]},
    {"limitations":["backport_unverified"]}, {"cve_ids":[]}])
def test_version_candidates_and_partial_evidence_do_not_pass(change):
    catalog,report=inputs();report["detections"][0].update(change)
    assert not benchmark.score_benchmark(catalog,report)["complete"]


def test_empty_or_unreviewed_catalog_cannot_claim_completeness():
    catalog,report=inputs();catalog["entries"]=[]
    assert not benchmark.score_benchmark(catalog,report)["complete"]
    catalog,report=inputs();catalog["catalog_complete"]=False
    assert not benchmark.score_benchmark(catalog,report)["complete"]
    catalog["reviewer"]=""
    with pytest.raises(ValueError):benchmark.score_benchmark(catalog,report)


def test_manual_population_and_hardened_controls_scored_separately():
    catalog,report=inputs();entry=catalog["entries"][0]
    entry.update(eligibility="manual_only",population="later_advisory")
    assert benchmark.score_benchmark(catalog,report)["results"][0]["status"]=="manual_pending"
    report["manual_results"]=[dict(report["detections"][0], issue_id="i1",reviewed=True,outcome="observed_condition")]
    result=benchmark.score_benchmark(catalog,report)
    assert result["complete"] and result["populations"]["later_advisory"]["manual_verified"]==1
    catalog,report=inputs();catalog["entries"][0]["expectation"]="absent"
    result=benchmark.score_benchmark(catalog,report)
    assert not result["complete"] and result["results"][0]["status"]=="false_positive"


def test_report_from_another_scope_cannot_pass():
    catalog,report=inputs();report["scope_sha256"]="d"*64
    result=benchmark.score_benchmark(catalog,report)
    assert not result["complete"] and not result["scope_matches"]


@pytest.mark.parametrize("change", [{"target":"wrong"},{"role_id":"wrong"},{"rule_id":"wrong"},
    {"evidence_fields":[]},{"evidence_ids":["unlinked"]},{"cve_ids":[]},{"collection_complete":False}])
def test_manual_wrong_identity_or_incomplete_evidence_cannot_pass(change):
    catalog,report=inputs();catalog["entries"][0]["eligibility"]="manual_only"
    row=dict(report["detections"][0],issue_id="i1",reviewed=True,outcome="observed_condition")
    row.update(change);report["manual_results"]=[row]
    assert not benchmark.score_benchmark(catalog,report)["complete"]


def test_provenance_and_actual_evidence_are_bound_separately():
    catalog,report=inputs();report["provenance_sha256"]="e"*64
    assert not benchmark.score_benchmark(catalog,report)["complete"]
    catalog,report=inputs();report["evidence_index"][0]["source_action"]="unrelated"
    assert not benchmark.score_benchmark(catalog,report)["complete"]
    catalog,report=inputs();report["evidence_index"].append(dict(report["evidence_index"][0]))
    with pytest.raises(ValueError):benchmark.score_benchmark(catalog,report)


def test_incomplete_negative_control_and_conflicting_rows_are_not_success():
    catalog,report=inputs();catalog["entries"][0]["expectation"]="absent"
    report["detections"][0]["collection_complete"]=False
    assert benchmark.score_benchmark(catalog,report)["results"][0]["status"]=="insufficient_evidence"
    catalog,report=inputs();report["detections"].append(dict(report["detections"][0],disposition="not_observed"))
    result=benchmark.score_benchmark(catalog,report)
    assert not result["complete"] and result["results"][0]["status"]=="conflicting_results"


@pytest.mark.parametrize("raw", [b'{"schema":1,"schema":2}',b'{"entries":[{"target":"a","target":"b"}]}',
    b'{"detections":[{"role_id":"a","role_id":"b"}]}'])
def test_private_input_rejects_duplicate_keys(tmp_path,raw):
    import hashlib
    p=tmp_path/"data.json";p.write_bytes(raw);p.chmod(0o600)
    with pytest.raises(ValueError,match="duplicate"):
        benchmark.private_json(p,hashlib.sha256(raw).hexdigest())
