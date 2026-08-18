from __future__ import annotations

import base64
import json
import os

from fastapi import FastAPI, Request

from aegis.platform.supply_chain_security import SignedEnvelope, SupplyChainDenied, verify_receipt

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _decision(uid: str, allowed: bool, message: str) -> dict:
    return {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
            "response": {"uid": uid, "allowed": allowed, "status": {"message": message}}}


@app.get("/healthz")
def healthz() -> dict: return {"status": "ok"}


@app.post("/validate")
async def validate(request: Request) -> dict:
    review = await request.json()
    req = review.get("request", {})
    uid = str(req.get("uid", ""))
    try:
        pod = req["object"]
        images = [c["image"] for c in pod["spec"]["containers"]]
        if len(images) != 1 or "@sha256:" not in images[0]: raise SupplyChainDenied("IMMUTABLE_DIGEST_REQUIRED")
        encoded = pod.get("metadata", {}).get("annotations", {}).get("aegisdesk.dev/supply-chain-receipt")
        if not encoded: raise SupplyChainDenied("RECEIPT_REQUIRED")
        data = json.loads(base64.urlsafe_b64decode(encoded.encode()).decode())
        envelope = SignedEnvelope(payload=data["payload"], signature=data["signature"])
        public_key = base64.b64decode(os.environ["P11E_RECEIPT_PUBLIC_KEY"])
        verify_receipt(envelope, public_key, image=images[0])
        return _decision(uid, True, "verified immutable supply-chain receipt")
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, SupplyChainDenied) as exc:
        reason = exc.reason if isinstance(exc, SupplyChainDenied) else "RECEIPT_MALFORMED"
        return _decision(uid, False, reason)
