"""Checks image-signature *evidence* (e.g. `cosign verify --output json` results).

Actual signing and verification belongs to Member 2's supply-chain module.
"""

from detection.alerts import Finding


def scan_image(evidence: dict) -> list[Finding]:
    image = evidence["image"]
    digest = evidence.get("digest")
    signatures = evidence.get("signatures") or []
    findings = []

    if "@sha256:" not in image and not digest:
        findings.append(Finding(
            "IMG-003", f"Image '{image}' referenced by mutable tag without a digest", "med",
            "Deploy images by digest (image@sha256:...).",
            {"image": image}, key=image,
        ))

    if not signatures:
        findings.append(Finding(
            "IMG-001", f"No signature evidence for image '{image}'", "high",
            "Block deployment until the image is signed and verified.",
            {"image": image, "digest": digest, "signatures": []}, key=image,
        ))
        return findings

    expected = digest or (image.split("@", 1)[1] if "@" in image else None)
    bad = [
        s for s in signatures
        if not s.get("verified") or (expected and s.get("subject_digest") and s["subject_digest"] != expected)
    ]
    if bad and len(bad) == len(signatures):
        findings.append(Finding(
            "IMG-002", f"Signature for image '{image}' failed verification", "critical",
            "Treat the image as tampered: do not deploy, and rebuild from a trusted pipeline.",
            {"image": image, "expected_digest": expected, "failed_signatures": bad}, key=image,
        ))
    return findings
