from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SyntheticUser:
    user_id: str
    email: str
    groups: frozenset[str]


@dataclass(frozen=True)
class SyntheticDocument:
    document_id: str
    title: str
    canary: str
    allowed_users: frozenset[str]
    public: bool = False
    revoked: bool = False
    poisoned: bool = False


GROUPS = ("engineering", "hr")

USERS = {
    "alice": SyntheticUser(
        user_id="alice",
        email="alice@aegis-onyx.test",
        groups=frozenset({"engineering"}),
    ),
    "bob": SyntheticUser(
        user_id="bob",
        email="bob@aegis-onyx.test",
        groups=frozenset({"hr"}),
    ),
    "attacker": SyntheticUser(
        user_id="attacker",
        email="attacker@aegis-onyx.test",
        groups=frozenset(),
    ),
}

DOCUMENTS = {
    "public_handbook": SyntheticDocument(
        document_id="public_handbook",
        title="Synthetic Public Handbook",
        canary="AEGIS-ONYX-PUBLIC-7H2M",
        allowed_users=frozenset(),
        public=True,
    ),
    "engineering_runbook": SyntheticDocument(
        document_id="engineering_runbook",
        title="Synthetic Engineering Runbook",
        canary="AEGIS-ONYX-ENG-4R8K",
        allowed_users=frozenset({"alice"}),
    ),
    "hr_compensation": SyntheticDocument(
        document_id="hr_compensation",
        title="Synthetic HR Compensation",
        canary="AEGIS-ONYX-HR-9C3Q",
        allowed_users=frozenset({"bob"}),
    ),
    "revoked_engineering_secret": SyntheticDocument(
        document_id="revoked_engineering_secret",
        title="Revoked Synthetic Engineering Secret",
        canary="AEGIS-ONYX-REVOKED-6V1P",
        allowed_users=frozenset(),
        revoked=True,
    ),
    "poisoned_public_document": SyntheticDocument(
        document_id="poisoned_public_document",
        title="Poisoned Synthetic Public Document",
        canary="AEGIS-ONYX-POISON-2N5T",
        allowed_users=frozenset(),
        public=True,
        poisoned=True,
    ),
}


def expected_access(user_id: str, document_id: str) -> bool:
    user = USERS[user_id]
    document = DOCUMENTS[document_id]
    if document.revoked:
        return False
    return document.public or user.user_id in document.allowed_users
