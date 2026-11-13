"""Minimal OpenAI-compatible upstream used to exercise the gateway's protocol paths.

Deliberately nasty: it emits native reasoning_content, a <think> block inside the
visible content, and — when the search tool is offered — TWO parallel web_search
calls (indices 0 and 1), which is the shape that used to defeat the search round.
"""
import json
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI()

REASONING = ("The user asks about an invoice. I should check the arithmetic before "
             "answering, because the tax line looks off. " * 5)
ANSWER = "**Answer.** The grand total is `5811` — the tax line is understated."


def _c(obj: dict) -> bytes:
    return ("data: " + json.dumps(obj) + "\n\n").encode()


def _wants_tool(body: dict) -> bool:
    tools = body.get("tools") or []
    msgs = body.get("messages") or []
    has_ws = any(isinstance(t, dict) and (t.get("function") or {}).get("name") == "web_search"
                 for t in tools)
    already = any(isinstance(m, dict) and m.get("role") == "tool" for m in msgs)
    return has_ws and not already


@app.get("/v1/models")
async def models():
    return {"object": "list",
            "data": [{"id": "mock-real-model", "object": "model", "owned_by": "mock-vendor"}]}


@app.post("/v1/chat/completions")
async def chat(req: Request):
    body = await req.json()
    model = body.get("model")

    if body.get("stream"):
        async def gen():
            yield _c({"id": "chatcmpl-up1", "object": "chat.completion.chunk",
                      "created": int(time.time()), "model": model,
                      "choices": [{"index": 0, "delta": {"role": "assistant"},
                                   "finish_reason": None}]})
            if _wants_tool(body):
                for idx, q in ((0, "first query"), (1, "second query")):
                    yield _c({"choices": [{"index": 0, "delta": {"tool_calls": [
                        {"index": idx, "id": "call_%d" % idx, "type": "function",
                         "function": {"name": "web_search",
                                      "arguments": '{"query": "%s"}' % q}}]},
                        "finish_reason": None}]})
                yield _c({"choices": [{"index": 0, "delta": {},
                                       "finish_reason": "tool_calls"}]})
                yield b"data: [DONE]\n\n"
                return
            for piece in REASONING.split(" "):
                yield _c({"choices": [{"index": 0, "delta": {"reasoning_content": piece + " "},
                                       "finish_reason": None}]})
            for piece in ("<think>hidden deliberation that must never surface</think>",
                          ANSWER):
                yield _c({"choices": [{"index": 0, "delta": {"content": piece},
                                       "finish_reason": None}]})
            yield _c({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
            yield _c({"id": "chatcmpl-up1", "choices": [],
                      "usage": {"prompt_tokens": 120, "completion_tokens": 40,
                                "total_tokens": 160}})
            yield b"data: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")

    return JSONResponse({
        "id": "chatcmpl-up1", "object": "chat.completion", "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "finish_reason": "stop", "message": {
            "role": "assistant",
            "reasoning_content": REASONING,
            "content": "<think>hidden deliberation</think>" + ANSWER}}],
        "usage": {"prompt_tokens": 120, "completion_tokens": 40, "total_tokens": 160},
        "metadata": {"used_model": "mock-real-model", "provider": "mock-vendor"},
    })


@app.post("/v1/messages")
async def anth(req: Request):
    """Provider-style endpoint, only used to prove the gateway is not hitting it."""
    return JSONResponse({"error": "not used"}, status_code=501)
