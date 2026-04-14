from __future__ import annotations

from ..registry import detector, BaseDetector
from ..models import Priority, JudgeMode, Capability, ProbeRequest, ProbeResponse, DetectorResult
from ..assets import aget_probe_audio, to_base64

_EXPECTED_WORDS = ("CRIMSON", "FORTY", "TWO")


@detector
class D27d_AudioFidelityProbe(BaseDetector):
    detector_id = "D27d"
    detector_name = "AudioFidelityProbe"
    priority = Priority.P1
    judge_mode = JudgeMode.MAJORITY_2_OF_2
    request_count = 2
    required_capabilities = (Capability.AUDIO,)
    description = "Detect audio multimodal degradation via TTS-generated speech"

    async def send_probes(self) -> list[ProbeResponse]:
        audio_bytes, text = await aget_probe_audio()
        if audio_bytes is None:
            return [ProbeResponse(status_code=0, error="TTS_UNAVAILABLE")]
        self._expected = text
        b64 = to_base64(audio_bytes)
        return [await self.client.send(ProbeRequest(
            payload={"model": self.config.claimed_model, "temperature": 0, "max_tokens": 12,
                     "messages": [{"role": "user", "content": [
                         {"type": "text", "text": "Output only the verification nonce spoken in the audio. Nothing else."},
                         {"type": "input_audio", "input_audio": {"data": b64, "format": "wav"}}]}]},
            endpoint_path=self.config.default_endpoint_path, description="audio probe"))]

    def judge(self, responses: list[ProbeResponse]) -> DetectorResult:
        r = responses[0]
        if r.is_network_error:
            return self._inconclusive(r.error or "network error")
        content = r.content.upper()
        if all(w in content for w in _EXPECTED_WORDS):
            return self._pass({"transcription": r.content.strip()})
        return self._fail("audio transcription incorrect", {"expected": " ".join(_EXPECTED_WORDS), "got": r.content.strip()})

    @classmethod
    def _test_cases(cls):
        return [
            ("PASS: correct transcription", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "CRIMSON FORTY TWO"}, "finish_reason": "stop"}]})], "pass"),
            ("FAIL: wrong transcription", [ProbeResponse(status_code=200, body={"choices": [{"message": {"content": "CHRISTMAS FOURTEEN"}, "finish_reason": "stop"}]})], "fail"),
            ("INCONCLUSIVE: network error", [ProbeResponse(status_code=0, error="TIMEOUT")], "inconclusive"),
        ]


if __name__ == "__main__":
    D27d_AudioFidelityProbe.self_test()
