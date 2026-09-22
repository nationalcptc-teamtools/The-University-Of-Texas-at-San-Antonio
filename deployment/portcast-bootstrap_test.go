package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestV7PlanSemanticHashMatchesFrozenPlan(t *testing.T) {
	raw, err := os.ReadFile("../testing/cptc11_lab/portcast-live-plan-v7.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, fields, err := decodeStartPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := semanticPlanSHA256(fields)
	if err != nil {
		t.Fatal(err)
	}
	if actual != plan.PlanSHA256 {
		t.Fatalf("semantic plan digest differs: got %s want %s", actual, plan.PlanSHA256)
	}
	if err := validateStartPlan(plan, fields); err != nil {
		t.Fatal(err)
	}
}

func TestV7PlanSemanticHashRejectsResealedMismatch(t *testing.T) {
	raw, err := os.ReadFile("../testing/cptc11_lab/portcast-live-plan-v7.json")
	if err != nil {
		t.Fatal(err)
	}
	_, fields, err := decodeStartPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	fields["plan_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
	mutated, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	plan, decoded, err := decodeStartPlan(mutated)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := semanticPlanSHA256(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if actual == plan.PlanSHA256 {
		t.Fatal("mutated semantic digest unexpectedly matches")
	}
	if err := validateStartPlan(plan, decoded); err == nil {
		t.Fatal("mutated plan unexpectedly passed static admission")
	}
}

func TestV7PlanValidationRejectsMissingAndExtraFields(t *testing.T) {
	raw, err := os.ReadFile("../testing/cptc11_lab/portcast-live-plan-v7.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"missing", "extra"} {
		t.Run(mutation, func(t *testing.T) {
			_, fields, err := decodeStartPlan(raw)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "missing" {
				delete(fields, "roe_reference")
			} else {
				fields["unexpected_field"] = "unexpected"
			}
			semantic, err := semanticPlanSHA256(fields)
			if err != nil {
				t.Fatal(err)
			}
			fields["plan_sha256"] = semantic
			mutated, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			plan, decoded, err := decodeStartPlan(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateStartPlan(plan, decoded); err == nil {
				t.Fatal("mutated plan unexpectedly passed static admission")
			}
		})
	}
}

func TestV7PlanDecoderRejectsAmbiguousJSON(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"action_id":"one","action_id":"two","release_id":"portcast-live-v1","plan_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`),
		[]byte(`{"action_id":"one","release_id":"portcast-live-v1","plan_sha256":"0000000000000000000000000000000000000000000000000000000000000000","nested":{}}`),
		[]byte(`{"action_id":"one","release_id":"portcast-live-v1","plan_sha256":"0000000000000000000000000000000000000000000000000000000000000000"} true`),
	} {
		if _, _, err := decodeStartPlan(raw); err == nil {
			t.Fatalf("ambiguous plan was accepted: %s", raw)
		}
	}
}
