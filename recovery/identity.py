"""Credential rotation adapters.

Only a simulated provider ships. A real provider (Vault, AWS IAM, GitHub App, ...) implements the same
`rotate` method and is selected with RECOVERY_IDENTITY_PROVIDER; it must never return secret values.
"""

import os
from typing import Protocol
from uuid import uuid4


class RotationError(Exception):
    pass


class IdentityProvider(Protocol):
    name: str
    simulated: bool

    def rotate(self, credential: str) -> dict:
        """Issue a replacement for `credential` and return non-secret metadata about it."""


class SimulatedIdentityProvider:
    name = "simulated"
    simulated = True

    def rotate(self, credential: str) -> dict:
        return {"credential": credential, "new_version": uuid4().hex[:12], "simulated": True,
                "note": "no real credential was issued; rotate it in the real identity provider"}


def get_provider() -> IdentityProvider:
    name = os.getenv("RECOVERY_IDENTITY_PROVIDER", "simulated")
    if name == "simulated":
        return SimulatedIdentityProvider()
    raise RotationError(f"identity provider '{name}' is not implemented")
