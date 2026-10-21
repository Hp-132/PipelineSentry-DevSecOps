package pipelinesentry.workflow_test

import rego.v1

import data.pipelinesentry.workflow

sha := "11bd71901bbe5b1630ceea73d27597364c9af683"

good := {
	"name": "CI",
	"permissions": {"contents": "read"},
	"jobs": {"test": {
		"runs-on": "ubuntu-latest",
		"steps": [{"uses": concat("", ["actions/checkout@", sha])}, {"uses": "./local-action"}, {"run": "make test"}],
	}},
}

violation_ids(wf, triggers) := result if {
	result := {v.rule_id | some v in workflow.violations} with input as {"path": "ci.yml", "triggers": triggers, "workflow": wf}
}

test_compliant_workflow_allowed if {
	workflow.allow with input as {"path": "ci.yml", "triggers": ["pull_request"], "workflow": good}
}

test_tag_pinned_action_denied if {
	wf := json.patch(good, [{"op": "replace", "path": "/jobs/test/steps/0/uses", "value": "actions/checkout@v4"}])
	"POL-WF-001" in violation_ids(wf, ["push"])
}

test_short_sha_is_not_pinned if {
	wf := json.patch(good, [{"op": "replace", "path": "/jobs/test/steps/0/uses", "value": "actions/checkout@11bd719"}])
	"POL-WF-001" in violation_ids(wf, ["push"])
}

test_unpinned_reusable_workflow_denied if {
	wf := json.patch(good, [{"op": "add", "path": "/jobs/release", "value": {"uses": "org/repo/.github/workflows/r.yml@main"}}])
	"POL-WF-001" in violation_ids(wf, ["push"])
}

test_write_all_denied if {
	wf := json.patch(good, [{"op": "replace", "path": "/permissions", "value": "write-all"}])
	"POL-WF-002" in violation_ids(wf, ["push"])
}

test_missing_permissions_flagged if {
	wf := json.patch(good, [{"op": "remove", "path": "/permissions"}])
	"POL-WF-002" in violation_ids(wf, ["push"])
}

test_job_level_permissions_are_enough if {
	wf := json.patch(good, [
		{"op": "remove", "path": "/permissions"},
		{"op": "add", "path": "/jobs/test/permissions", "value": {"contents": "read"}},
	])
	not "POL-WF-002" in violation_ids(wf, ["push"])
}

test_self_hosted_on_pull_request_denied if {
	wf := json.patch(good, [{"op": "replace", "path": "/jobs/test/runs-on", "value": ["self-hosted", "linux"]}])
	"POL-WF-003" in violation_ids(wf, ["pull_request_target"])
}

test_self_hosted_on_push_allowed if {
	wf := json.patch(good, [{"op": "replace", "path": "/jobs/test/runs-on", "value": "self-hosted"}])
	not "POL-WF-003" in violation_ids(wf, ["push"])
}

test_unpinned_job_container_flagged if {
	wf := json.patch(good, [{"op": "add", "path": "/jobs/test/container", "value": {"image": "node:20"}}])
	"POL-WF-004" in violation_ids(wf, ["push"])
}
