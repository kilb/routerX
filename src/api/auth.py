"""Bearer token auth: API key comes from ``AUDITOR_API_KEY`` env var."""
from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer()


def get_api_key() -> str:
    key = os.environ.get("AUDITOR_API_KEY")
    if not key:
        raise RuntimeError("AUDITOR_API_KEY environment variable is not set")
    return key


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    # Constant-time comparison to prevent timing attacks that could leak
    # key length or prefix through response-time side channels.
    if not hmac.compare_digest(credentials.credentials, get_api_key()):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials
