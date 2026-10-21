package pipelinesentry.kubernetes_test

import rego.v1

import data.pipelinesentry.kubernetes

cfg := {"allowed_registries": ["registry:5000"], "blocked_images": []}

digest := "sha256:4e6f2b1c7d8a9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081"

good_container := {
	"name": "app",
	"image": concat("", ["registry:5000/demo/app@", digest]),
	"securityContext": {"allowPrivilegeEscalation": false, "runAsNonRoot": true},
	"resources": {"limits": {"cpu": "100m"}},
}

deployment(container, extra_spec) := {
	"kind": "Deployment",
	"metadata": {"name": "app"},
	"spec": {"template": {"spec": object.union({"containers": [container]}, extra_spec)}},
}

violation_ids(resources, config) := ids if {
	ids := {v.rule_id | some v in kubernetes.violations} with input as {"resources": resources}
		with data.config as config
}

test_compliant_deployment_allowed if {
	kubernetes.allow with input as {"resources": [deployment(good_container, {})]} with data.config as cfg
}

test_privileged_container_denied if {
	c := object.union(good_container, {"securityContext": {"privileged": true, "allowPrivilegeEscalation": false, "runAsNonRoot": true}})
	"POL-K8S-001" in violation_ids([deployment(c, {})], cfg)
}

test_privilege_escalation_must_be_disabled if {
	c := object.remove(good_container, ["securityContext"])
	ids := violation_ids([deployment(c, {"securityContext": {"runAsNonRoot": true}})], cfg)
	"POL-K8S-002" in ids
	not "POL-K8S-008" in ids
}

test_host_namespace_denied if {
	"POL-K8S-003" in violation_ids([deployment(good_container, {"hostPID": true})], cfg)
}

test_host_path_denied if {
	spec := {"volumes": [{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}]}
	"POL-K8S-004" in violation_ids([deployment(good_container, spec)], cfg)
}

test_tag_only_image_denied if {
	c := object.union(good_container, {"image": "registry:5000/demo/app:1.0"})
	ids := violation_ids([deployment(c, {})], cfg)
	"POL-K8S-005" in ids
	not "POL-K8S-006" in ids
}

test_unapproved_registry_denied if {
	c := object.union(good_container, {"image": concat("", ["docker.io/evil/app@", digest])})
	ids := violation_ids([deployment(c, {})], cfg)
	"POL-K8S-006" in ids
	not "POL-K8S-005" in ids
}

test_registry_prefix_must_match_whole_host if {
	c := object.union(good_container, {"image": concat("", ["registry:5000.evil.test/app@", digest])})
	"POL-K8S-006" in violation_ids([deployment(c, {})], cfg)
}

test_blocked_image_denied if {
	blocked := object.union(cfg, {"blocked_images": [good_container.image]})
	"POL-K8S-007" in violation_ids([deployment(good_container, {})], blocked)
}

test_root_container_flagged if {
	c := object.union(object.remove(good_container, ["securityContext"]), {"securityContext": {"allowPrivilegeEscalation": false}})
	"POL-K8S-008" in violation_ids([deployment(c, {})], cfg)
}

test_dangerous_capability_denied if {
	c := object.union(good_container, {"securityContext": {
		"allowPrivilegeEscalation": false, "runAsNonRoot": true,
		"capabilities": {"add": ["sys_admin"]},
	}})
	"POL-K8S-009" in violation_ids([deployment(c, {})], cfg)
}

test_missing_limits_flagged if {
	c := object.remove(good_container, ["resources"])
	"POL-K8S-010" in violation_ids([deployment(c, {})], cfg)
}

test_init_containers_checked if {
	bad := object.union(good_container, {"name": "init", "securityContext": {"privileged": true}})
	"POL-K8S-001" in violation_ids([deployment(good_container, {"initContainers": [bad]})], cfg)
}

test_pod_and_cronjob_specs_checked if {
	bad := object.union(good_container, {"securityContext": {"privileged": true}})
	pod := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": [bad]}}
	cron := {"kind": "CronJob", "metadata": {"name": "c"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [bad]}}}}}}
	resources := {v.resource | some v in kubernetes.violations; v.rule_id == "POL-K8S-001"} with input as {"resources": [pod, cron]}
		with data.config as cfg
	resources == {"Pod/p", "CronJob/c"}
}

test_non_workloads_ignored if {
	cm := {"kind": "ConfigMap", "metadata": {"name": "x"}, "data": {"a": "b"}}
	kubernetes.allow with input as {"resources": [cm]} with data.config as cfg
}
