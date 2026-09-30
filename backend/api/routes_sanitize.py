"""File and link sanitization endpoints.

Files arrive as a raw request body with the name in the query string, which
avoids a multipart dependency and lets the size cap be enforced while the body
streams in rather than after it has been buffered.
"""
import os
import sys

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from services import sanitizer

router = APIRouter()


class LinkRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    trace: bool = False


@router.post("/sanitize/link")
async def sanitize_link(body: LinkRequest):
    return sanitizer.analyze_link(body.url, trace=body.trace)


@router.post("/sanitize/file")
async def sanitize_file(request: Request, filename: str = Query(..., min_length=1, max_length=255)):
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > sanitizer.MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File too large")
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > sanitizer.MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail="File too large")
        chunks.append(chunk)
    return sanitizer.analyze_file(filename, b"".join(chunks))
