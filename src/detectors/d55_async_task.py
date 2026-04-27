from __future__ import annotations

import asyncio

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ProbeRequest, ProbeResponse, DetectorResult

_VALID_STATUSES = {"queued", "running", "succeeded", "completed", "failed"}


@detector
class D55_AsyncTaskProbe(BaseDetector):
    detector_id = "D55"
    detector_name = "AsyncTaskProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.ONCE
    request_count = 2
    detector_timeout = 120.0
    required_capabilities = (Capability.TASK_MODEL,)
    description = "Detect async task forgery, local fake queue, or cache replay"

    async def send_probes(self) -> list[ProbeResponse]:
        cfg = self.config.task_model_config
        all_resps: list[ProbeResponse] = []
        for nonce in ("NONCE-A7M2", "NONCE-B8K5"):
            create = await self.client.send(ProbeRequest(
                payload={"model": self.config.claimed_model,
                         "prompt": f"A red ball on white floor. Text {nonce} in frame.", "duration": 5},
                endpoint_path=cfg.create_endpoint, description=f"create {nonce}"))
            all_resps.append(create)
            if create.is_network_error or create.status_code != 200:
                continue
            tid = (create.body or {}).get(cfg.task_id_field, "")
            if not tid:
                continue
            poll_path = cfg.poll_endpoint.replace("{task_id}", str(tid))
            final = None
            for _ in range(cfg.max_poll_attempts):
                await asyncio.sleep(cfg.poll_interval_seconds)
                poll = await self.client.get(poll_path)
                status = (poll.body or {}).get("status", "")
                if status in ("succeeded", "failed", "completed"):
                    final = poll
                    break
            all_resps.append(final or ProbeResponse(status_code=0, error="POLL_TIMEOUT"))
            if nonce == "NONCE-A7M2":
                await asyncio.sleep(5)
        return all_resps

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        cfg = self.config.task_model_config
        # In self_test, cfg is a MagicMock — getattr returns another Mock.
        # Guard with isinstance so we always fall back to "task_id".
        raw = getattr(cfg, "task_id_field", None) if cfg else None
        tid_field = raw if isinstance(raw, str) else "task_id"
        creates = [r for r in responses if r.body and tid_field in (r.body or {})]
        if len(creates) < 2:
            return self._pass({"note": "could not create both tasks — no evidence of issue"})
        id_a, id_b = creates[0].body[tid_field], creates[1].body[tid_field]
        if id_a == id_b:
            return self._fail("same task_id for both tasks", {"id_a": id_a, "id_b": id_b})
        polls = [r for r in responses if r.body and "status" in (r.body or {}) and tid_field not in (r.body or {})]
        for p in polls:
            st = (p.body or {}).get("status", "")
            if st and st not in _VALID_STATUSES:
                return self._fail(f"invalid status: {st}", {"status": st})
        artifacts = []
        for p in polls:
            url = (p.body or {}).get("artifact_url") or (p.body or {}).get("result_url")
            if url:
                artifacts.append(url)
        if len(artifacts) >= 2 and artifacts[0] == artifacts[1]:
            return self._fail("identical artifacts (cache replay)", {"url_a": artifacts[0]})
        return self._pass({"id_a": id_a, "id_b": id_b})

    @classmethod
    def _test_cases(cls):
        c1 = ProbeResponse(status_code=200, body={"task_id": "t1", "status": "queued"})
        c2 = ProbeResponse(status_code=200, body={"task_id": "t2", "status": "queued"})
        p1 = ProbeResponse(status_code=200, body={"status": "succeeded", "artifact_url": "/a/1"})
        p2 = ProbeResponse(status_code=200, body={"status": "succeeded", "artifact_url": "/a/2"})
        p_dup = ProbeResponse(status_code=200, body={"status": "succeeded", "artifact_url": "/a/1"})
        c_dup = ProbeResponse(status_code=200, body={"task_id": "t1", "status": "queued"})
        return [
            ("PASS: unique tasks", [c1, p1, c2, p2], "pass"),
            ("FAIL: same task_id", [c1, p1, c_dup, p2], "fail"),
            ("FAIL: identical artifacts", [c1, p1, c2, p_dup], "fail"),
            ("PASS: creation failed", [ProbeResponse(status_code=0, error="X")], "pass"),
        ]


if __name__ == "__main__":
    D55_AsyncTaskProbe.self_test()
