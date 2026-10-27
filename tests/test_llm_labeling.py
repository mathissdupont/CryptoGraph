from __future__ import annotations

from cryptograph.llm_labeling import assess_pqc, simulate_label


def test_label_script_writes_utf8_with_ascii_console(tmp_path) -> None:
    import json
    import os
    import subprocess
    import sys

    from cryptograph.utils import project_path

    asset = {
        "asset_id": "example",
        "input": {"crypto_metadata": {"algorithm": "SHA-256", "primitive": "hash"}},
        "note": "Türkçe açıklama",
    }
    (tmp_path / "dataset.jsonl").write_text(json.dumps(asset) + "\n", encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="ascii")
    result = subprocess.run(
        [sys.executable, str(project_path("scripts", "llm-label-cbom.py")),
         "--input", "dataset.jsonl", "--output", "nested/baseline.jsonl", "--llm-api", "simulate"],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    labeled = json.loads((tmp_path / "nested" / "baseline.jsonl").read_text(encoding="utf-8"))
    assert labeled["note"] == asset["note"]


def test_assess_pqc_marks_rsa_as_quantum_vulnerable() -> None:
    asset = {
        "input": {
            "metadata": {"detected_language": "java"},
            "crypto_metadata": {
                "algorithm": "RSA",
                "primitive": "asymmetric_key_generation",
                "key_size": 2048,
            },
        }
    }

    pqc = assess_pqc(asset)

    assert pqc["compatible"] is False
    assert pqc["status"] == "quantum-vulnerable"
    assert pqc["migration_priority"] == "high"


def test_assess_pqc_marks_aes_as_quantum_resilient_with_parameters() -> None:
    asset = {
        "input": {
            "metadata": {"detected_language": "javascript"},
            "crypto_metadata": {
                "algorithm": "AES",
                "primitive": "symmetric_encryption",
                "mode": "GCM",
                "key_size": 256,
            },
        }
    }

    pqc = assess_pqc(asset)

    assert pqc["compatible"] is True
    assert pqc["status"] == "quantum-resilient-with-parameters"


def test_simulate_label_includes_pqc_block() -> None:
    asset = {
        "input": {
            "metadata": {"detected_language": "csharp"},
            "crypto_metadata": {
                "algorithm": "SHA-1",
                "primitive": "hash",
            },
        }
    }

    label = simulate_label(asset)

    assert label["schema_version"] == "1.1"
    assert label["risk_level"] == "high"
    assert "pqc" in label
    assert "pqc_compatible" in label
    assert label["language"] == "csharp"
