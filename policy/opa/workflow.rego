# GitHub Actions workflow policies (a pre-merge gate; complements Member 1's detection rules).
#   input: {"path": "...", "triggers": ["push", ...], "workflow": <parsed YAML with the `on` key normalised>}
package pipelinesentry.workflow

import rego.v1

violation(rule_id, severity, location, message) := {
	"rule_id": rule_id,
	"severity": severity,
	"resource": sprintf("%s:%s", [input.path, location]),
	"message": message,
}

jobs contains [job_id, job] if {
	some job_id, job in object.get(input.workflow, "jobs", {})
}

steps contains [job_id, i, step] if {
	some pair in jobs
	[job_id, job] := pair
	some i, step in object.get(job, "steps", [])
}

pinned_to_commit(uses) if regex.match(`@[0-9a-f]{40}$`, uses)

local_or_docker(uses) if startswith(uses, "./")

local_or_docker(uses) if startswith(uses, "docker://")

violations contains v if {
	some s in steps
	[job_id, i, step] := s
	uses := step.uses
	not local_or_docker(uses)
	not pinned_to_commit(uses)
	v := violation(
		"POL-WF-001", "med", sprintf("%s.steps[%d]", [job_id, i]),
		sprintf("action '%s' is not pinned to a full commit SHA", [uses]),
	)
}

# Reusable workflows called at job level follow the same rule
violations contains v if {
	some pair in jobs
	[job_id, job] := pair
	uses := job.uses
	not startswith(uses, "./")
	not pinned_to_commit(uses)
	v := violation("POL-WF-001", "med", job_id, sprintf("reusable workflow '%s' is not pinned to a full commit SHA", [uses]))
}

violations contains v if {
	input.workflow.permissions == "write-all"
	v := violation("POL-WF-002", "high", "permissions", "workflow grants write-all permissions")
}

violations contains v if {
	not "permissions" in object.keys(input.workflow)
	some pair in jobs
	[job_id, job] := pair
	not "permissions" in object.keys(job)
	v := violation("POL-WF-002", "med", job_id, "no permissions block: the job gets the repository's default token scope")
}

untrusted_triggers := {"pull_request", "pull_request_target", "issue_comment", "workflow_run"}

self_hosted(job) if "self-hosted" in job["runs-on"]

self_hosted(job) if job["runs-on"] == "self-hosted"

violations contains v if {
	some trigger in input.triggers
	trigger in untrusted_triggers
	some pair in jobs
	[job_id, job] := pair
	self_hosted(job)
	v := violation(
		"POL-WF-003", "high", job_id,
		sprintf("self-hosted runner used by a workflow triggered by '%s' (untrusted code)", [trigger]),
	)
}

job_image(job) := job.container if is_string(job.container)

job_image(job) := job.container.image if is_object(job.container)

violations contains v if {
	some pair in jobs
	[job_id, job] := pair
	image := job_image(job)
	not contains(image, "@sha256:")
	v := violation("POL-WF-004", "med", job_id, sprintf("job container image '%s' is not pinned by digest", [image]))
}

allow if count(violations) == 0
