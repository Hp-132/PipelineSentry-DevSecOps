# Kubernetes workload policies.
#   input: {"resources": [<parsed manifest>, ...]}
#   data.config: {"allowed_registries": [...], "blocked_images": [...]}  (supplied by policy/evaluator.py)
package pipelinesentry.kubernetes

import rego.v1

workload_kinds := {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

pod_spec(r) := r.spec if r.kind == "Pod"

pod_spec(r) := r.spec.jobTemplate.spec.template.spec if r.kind == "CronJob"

pod_spec(r) := r.spec.template.spec if {
	not r.kind in {"Pod", "CronJob"}
}

resource_name(r) := sprintf("%s/%s", [r.kind, object.get(r, ["metadata", "name"], "unnamed")])

violation(rule_id, severity, r, message) := {
	"rule_id": rule_id,
	"severity": severity,
	"resource": resource_name(r),
	"message": message,
}

workloads contains r if {
	some r in input.resources
	r.kind in workload_kinds
}

# [resource, container] pairs, including init and ephemeral containers
containers contains [r, c] if {
	some r in workloads
	some field in ["initContainers", "containers", "ephemeralContainers"]
	some c in object.get(pod_spec(r), field, [])
}

violations contains v if {
	some pair in containers
	[r, c] := pair
	c.securityContext.privileged == true
	v := violation("POL-K8S-001", "critical", r, sprintf("container '%s' runs privileged", [c.name]))
}

violations contains v if {
	some pair in containers
	[r, c] := pair
	object.get(c, ["securityContext", "allowPrivilegeEscalation"], true) != false
	v := violation(
		"POL-K8S-002", "high", r,
		sprintf("container '%s' must set securityContext.allowPrivilegeEscalation: false", [c.name]),
	)
}

violations contains v if {
	some r in workloads
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	object.get(pod_spec(r), field, false) == true
	v := violation("POL-K8S-003", "high", r, sprintf("pod shares the host namespace (%s: true)", [field]))
}

violations contains v if {
	some r in workloads
	some volume in object.get(pod_spec(r), "volumes", [])
	volume.hostPath
	v := violation("POL-K8S-004", "high", r, sprintf("volume '%s' mounts a hostPath (%s)", [volume.name, volume.hostPath.path]))
}

violations contains v if {
	some pair in containers
	[r, c] := pair
	not contains(c.image, "@sha256:")
	v := violation("POL-K8S-005", "high", r, sprintf("image '%s' is not pinned by digest", [c.image]))
}

allowed_registry(image) if {
	some registry in data.config.allowed_registries
	startswith(image, concat("", [registry, "/"]))
}

violations contains v if {
	some pair in containers
	[r, c] := pair
	not allowed_registry(c.image)
	v := violation("POL-K8S-006", "high", r, sprintf("image '%s' is not from an approved registry", [c.image]))
}

# Images blocked by PipelineSentry's response engine (or listed in config) can never be admitted
violations contains v if {
	some pair in containers
	[r, c] := pair
	some blocked in data.config.blocked_images
	c.image == blocked
	v := violation("POL-K8S-007", "critical", r, sprintf("image '%s' is blocked by an incident response", [c.image]))
}

runs_as_non_root(r, c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(r, c) if {
	pod_spec(r).securityContext.runAsNonRoot == true
	not c.securityContext.runAsNonRoot == false
}

violations contains v if {
	some pair in containers
	[r, c] := pair
	not runs_as_non_root(r, c)
	v := violation("POL-K8S-008", "med", r, sprintf("container '%s' may run as root (set runAsNonRoot: true)", [c.name]))
}

dangerous_capabilities := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"}

violations contains v if {
	some pair in containers
	[r, c] := pair
	some capability in object.get(c, ["securityContext", "capabilities", "add"], [])
	upper(capability) in dangerous_capabilities
	v := violation("POL-K8S-009", "high", r, sprintf("container '%s' adds capability %s", [c.name, capability]))
}

violations contains v if {
	some pair in containers
	[r, c] := pair
	not c.resources.limits
	v := violation("POL-K8S-010", "low", r, sprintf("container '%s' has no resource limits", [c.name]))
}

allow if count(violations) == 0
