"""Minimal OCI distribution-API client: resolve digests, check for cosign signature tags and push a
tiny demo image to the local registry (so the demo needs no Docker daemon inside the container)."""

import gzip
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass

import httpx

from shared import config

MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    tag: str | None
    digest: str | None

    @property
    def reference(self) -> str:
        return self.digest or self.tag or "latest"

    @property
    def insecure(self) -> bool:
        return self.registry in config.INSECURE_REGISTRIES

    def pinned(self, digest: str) -> str:
        return f"{self.registry}/{self.repository}@{digest}"


def parse(image: str) -> ImageRef:
    image = image.strip()
    if not image or any(c.isspace() for c in image):
        raise RegistryError(f"invalid image reference '{image}'")
    name, digest = (image.split("@", 1) + [None])[:2]
    if digest is not None and not DIGEST.match(digest):
        raise RegistryError(f"invalid digest in '{image}'")
    tag = None
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = name.rsplit(":", 1)
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first, rest
    else:
        registry, repository = "registry-1.docker.io", name if "/" in name else f"library/{name}"
    if not re.match(r"^[a-z0-9]+([._/-][a-z0-9]+)*$", repository):
        raise RegistryError(f"invalid repository name in '{image}'")
    return ImageRef(registry, repository, tag, digest)


class RegistryClient:
    def __init__(self, transport: httpx.BaseTransport | None = None, timeout: float = 10):
        self.client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=True)
        self.tokens: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.client.close()

    def _base(self, ref: ImageRef) -> str:
        return f"{'http' if ref.insecure else 'https'}://{ref.registry}/v2/{ref.repository}"

    def _request(self, method: str, ref: ImageRef, url: str, **kwargs) -> httpx.Response:
        headers = kwargs.pop("headers", {})
        if ref.registry in self.tokens:
            headers["Authorization"] = f"Bearer {self.tokens[ref.registry]}"
        try:
            response = self.client.request(method, url, headers=headers, **kwargs)
            if response.status_code == 401 and ref.registry not in self.tokens:
                self.tokens[ref.registry] = self._anonymous_token(response, ref)
                headers["Authorization"] = f"Bearer {self.tokens[ref.registry]}"
                response = self.client.request(method, url, headers=headers, **kwargs)
        except httpx.TransportError as exc:
            raise RegistryError(f"registry {ref.registry} unreachable: {exc.__class__.__name__}") from exc
        return response

    def _anonymous_token(self, response: httpx.Response, ref: ImageRef) -> str:
        challenge = response.headers.get("WWW-Authenticate", "")
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        if not challenge.lower().startswith("bearer") or "realm" not in params:
            raise RegistryError(f"registry {ref.registry} requires credentials")
        query = {"service": params.get("service", ""), "scope": f"repository:{ref.repository}:pull"}
        token = self.client.get(params["realm"], params=query)
        if token.status_code != 200:
            raise RegistryError(f"registry {ref.registry} refused an anonymous token ({token.status_code})")
        body = token.json()
        return body.get("token") or body.get("access_token") or ""

    def manifest_digest(self, ref: ImageRef, reference: str | None = None) -> str | None:
        """Digest of a manifest, or None if it does not exist."""
        url = f"{self._base(ref)}/manifests/{reference or ref.reference}"
        response = self._request("HEAD", ref, url, headers={"Accept": MANIFEST_TYPES})
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise RegistryError(f"registry returned {response.status_code} for {ref.repository}:{reference or ref.reference}")
        digest = response.headers.get("Docker-Content-Digest")
        if not digest:
            raise RegistryError("registry did not return Docker-Content-Digest")
        return digest

    def has_signature_tag(self, ref: ImageRef, digest: str) -> bool:
        """cosign stores signatures under the tag sha256-<hex>.sig."""
        return self.manifest_digest(ref, digest.replace(":", "-") + ".sig") is not None

    def _upload_blob(self, ref: ImageRef, data: bytes) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        start = self._request("POST", ref, f"{self._base(ref)}/blobs/uploads/")
        if start.status_code != 202:
            raise RegistryError(f"blob upload refused ({start.status_code})")
        location = start.headers["Location"]
        if location.startswith("/"):
            location = f"{'http' if ref.insecure else 'https'}://{ref.registry}{location}"
        put = self._request("PUT", ref, location, params={"digest": digest}, content=data,
                            headers={"Content-Type": "application/octet-stream"})
        if put.status_code != 201:
            raise RegistryError(f"blob upload failed ({put.status_code})")
        return digest

    def push_demo_image(self, ref: ImageRef, message: str) -> str:
        """Push a one-file image and return its manifest digest. Same message -> same digest."""
        if not ref.tag:
            raise RegistryError("push needs a tag")
        payload = message.encode()
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            info = tarfile.TarInfo("pipelinesentry-demo.txt")
            info.size, info.mtime, info.mode = len(payload), 0, 0o644
            tar.addfile(info, io.BytesIO(payload))
        layer_tar = tar_buffer.getvalue()
        layer = gzip.compress(layer_tar, mtime=0)
        image_config = json.dumps({
            "architecture": "amd64", "os": "linux", "config": {"Labels": {"org.pipelinesentry.demo": "true"}},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer_tar).hexdigest()]},
        }, sort_keys=True, separators=(",", ":")).encode()

        config_digest = self._upload_blob(ref, image_config)
        layer_digest = self._upload_blob(ref, layer)
        manifest = json.dumps({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest,
                       "size": len(image_config)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_digest,
                        "size": len(layer)}],
        }, sort_keys=True, separators=(",", ":")).encode()
        response = self._request("PUT", ref, f"{self._base(ref)}/manifests/{ref.tag}", content=manifest,
                                 headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
        if response.status_code != 201:
            raise RegistryError(f"manifest push failed ({response.status_code}): {response.text[:200]}")
        return "sha256:" + hashlib.sha256(manifest).hexdigest()
