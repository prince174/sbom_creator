import io
import json
import urllib.error
from unittest.mock import Mock

import pytest

from sbom_creator.core import build_candidates
from sbom_creator.llm import LlmConfig, OpenAICompatibleAssessor, _NoRedirect, _read_response


def catalog(count=1, metadata=None):
    image = {"artifacts": [{"id": str(index), "name": f"package-{index}", "type": "python", "version": "1",
                             "purl": f"pkg:pypi/package-{index}@1", "foundBy": "python-installed-package-cataloger",
                             "metadata": metadata or {"name": f"package-{index}", "version": "1"}}
                            for index in range(count)]}
    return build_candidates({"artifacts": []}, image)


def config(**overrides):
    return LlmConfig(**{"api_key": "", "base_url": "http://127.0.0.1:12345/v1", "model": "test", **overrides})


def envelope(candidates, **overrides):
    assessments = [{"candidate_id": c["candidate_id"], "tp_score": 91, "reason": "Exact identity in installed metadata",
                    "evidence_ids": [c["evidence"][0]["id"]], "missing_evidence": []} for c in candidates]
    return {"id": "response-test", "model": "reported-model",
            "choices": [{"finish_reason": "stop", "message": {"content": json.dumps({"assessments": assessments})}}],
            "usage": {"total_tokens": 123}, **overrides}


def fake_transport(monkeypatch, respond):
    calls = []
    def open_request(request, timeout):
        calls.append((request, timeout))
        answer = respond(json.loads(request.data))
        return io.BytesIO(answer if isinstance(answer, bytes) else json.dumps(answer).encode())
    opener = Mock()
    opener.open.side_effect = open_request
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: opener)
    return calls


def test_transport_batches_complete_candidates_and_records_audit(monkeypatch):
    candidates = catalog(3)
    index = {c["candidate_id"]: c for c in candidates}
    def respond(body):
        payload = json.loads(body["messages"][1]["content"])
        assert body["response_format"] == {"type": "json_object"}
        return envelope([index[c["candidate_id"]] for c in payload["candidates"]])
    calls = fake_transport(monkeypatch, respond)
    assessor = OpenAICompatibleAssessor(config(api_key="test-secret", batch_size=2, timeout_seconds=7))
    rows = assessor(candidates)
    assert len(rows) == 3 and len(calls) == 2
    assert all(timeout == 7 for _, timeout in calls)
    assert all(request.get_header("Authorization") == "Bearer test-secret" for request, _ in calls)
    assert "test-secret" not in json.dumps(assessor.audit)
    assert assessor.audit["mode"] == "llm"
    assert [batch["candidates"] for batch in assessor.audit["batches"]] == [2, 1]
    assert len(assessor.audit["prompt_sha256"]) == 64
    assert assessor.audit["batches"][0]["reported_model"] == "reported-model"


def test_metadata_projection_is_bounded_and_marks_truncation():
    assessor = OpenAICompatibleAssessor(config())
    batches = list(assessor._batches(catalog(metadata={"data": "x" * 100000})))
    artifact = batches[0][0]["evidence"][0]["artifact"]
    assert len(artifact["metadata_projection"]) == 4000
    assert artifact["metadata_truncated"] is True
    assert len(artifact["metadata_sha256"]) == 64


def test_single_oversized_candidate_fails_before_sending_any_request(monkeypatch):
    calls = fake_transport(monkeypatch, lambda body: {})
    with pytest.raises(ValueError, match="Single candidate"):
        OpenAICompatibleAssessor(config(max_bytes=2048))(catalog())
    assert calls == []


@pytest.mark.parametrize("mutate,match", [
    (lambda answer: answer["choices"][0].update(finish_reason="length"), "finish normally"),
    (lambda answer: answer["choices"][0]["message"].update(content='{"assessments": []}'), "every candidate"),
    (lambda answer: answer["choices"][0]["message"].update(content='{"assessments": [], "assessments": []}'), "Duplicate JSON"),
    (lambda answer: answer["choices"][0]["message"].update(content='```json\n{}\n```'), "Expecting value"),
    (lambda answer: answer["choices"][0]["message"].update(content='{"assessments": NaN}'), "Non-finite"),
])
def test_malformed_model_output_fails_without_fallback(monkeypatch, mutate, match):
    candidates = catalog()
    answer = envelope(candidates)
    mutate(answer)
    fake_transport(monkeypatch, lambda body: answer)
    with pytest.raises(ValueError, match=match):
        OpenAICompatibleAssessor(config())(candidates)


def test_unknown_evidence_from_model_is_rejected(monkeypatch):
    candidates = catalog()
    answer = envelope(candidates)
    result = json.loads(answer["choices"][0]["message"]["content"])
    result["assessments"][0]["evidence_ids"] = ["invented"]
    answer["choices"][0]["message"]["content"] = json.dumps(result)
    fake_transport(monkeypatch, lambda body: answer)
    with pytest.raises(ValueError, match="unknown or duplicate evidence"):
        OpenAICompatibleAssessor(config())(candidates)


def test_large_response_and_timeout_do_not_trigger_fallback(monkeypatch):
    fake_transport(monkeypatch, lambda body: b" " * 1025)
    with pytest.raises(ValueError, match="response exceeds"):
        OpenAICompatibleAssessor(config(max_response_bytes=1024))(catalog())
    opener = Mock()
    opener.open.side_effect = TimeoutError("sensitive endpoint not to expose")
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: opener)
    with pytest.raises(RuntimeError, match="transport failed") as error:
        OpenAICompatibleAssessor(config())(catalog())
    assert "sensitive" not in str(error.value)


def test_slow_trickle_response_has_elapsed_deadline(monkeypatch):
    stream = Mock()
    stream.read1.return_value = b"x"
    times = iter([1, 2, 4])
    monkeypatch.setattr("time.monotonic", lambda: next(times))
    with pytest.raises(TimeoutError, match="deadline"):
        _read_response(stream, 1000000, deadline=3)
    assert stream.read1.call_count == 2


@pytest.mark.parametrize("changes", [{"base_url": "http://remote.example/v1", "api_key": "secret"},
                                     {"base_url": "https://user:secret@remote.example/v1"},
                                     {"base_url": "https://remote.example/v1?token=secret"},
                                     {"base_url": "https://remote.example/v1"},
                                     {"timeout_seconds": float("inf")}, {"batch_size": 0},
                                     {"max_tokens": True}, {"model": ""}])
def test_config_rejects_unsafe_or_unbounded_settings(changes):
    with pytest.raises(ValueError):
        config(**changes)


def test_no_implicit_remote_model_configuration(monkeypatch):
    monkeypatch.delenv("SBOM_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("SBOM_LLM_MODEL", raising=False)
    with pytest.raises(RuntimeError, match="explicitly configured"):
        LlmConfig.from_environment()


def test_api_key_file_is_bounded_preferred_and_redacted(monkeypatch, tmp_path):
    keyfile = tmp_path / "llm.key"
    keyfile.write_text("file-secret\n", encoding="utf-8")
    monkeypatch.setenv("SBOM_LLM_BASE_URL", "https://model.example/v1")
    monkeypatch.setenv("SBOM_LLM_MODEL", "configured-model")
    monkeypatch.setenv("SBOM_LLM_API_KEY", "ignored-env-secret")
    monkeypatch.setenv("SBOM_LLM_API_KEY_FILE", str(keyfile))
    configured = LlmConfig.from_environment()
    assert configured.api_key == "file-secret"
    assert "file-secret" not in repr(configured)
    assert "file-secret" not in json.dumps(configured.public_settings())
    keyfile.write_bytes(b"s" * 8193)
    with pytest.raises(ValueError, match="size limit"):
        LlmConfig.from_environment()
    keyfile.unlink()
    with pytest.raises(RuntimeError, match="cannot be read"):
        LlmConfig.from_environment()


@pytest.mark.parametrize("key", ["secret\r\nInjected: value", "a" * 8193])
def test_secret_headers_reject_unbounded_or_injected_keys(key):
    with pytest.raises(ValueError, match="API key must be bounded"):
        config(api_key=key)


def test_redirect_handler_does_not_forward_authorization():
    request = urllib.request.Request("https://original.example/v1", headers={"Authorization": "Bearer secret"})
    with pytest.raises(urllib.error.HTTPError, match="redirects are forbidden"):
        _NoRedirect().redirect_request(request, None, 302, "redirect", {}, "https://other.example/v1")


def test_empty_catalog_needs_no_network_and_has_empty_assessments(monkeypatch):
    calls = fake_transport(monkeypatch, lambda body: {})
    assessor = OpenAICompatibleAssessor(config())
    assert assessor([]) == []
    assert assessor.audit["mode"] == "llm"
    assert assessor.audit["batches"] == []
    assert calls == []
