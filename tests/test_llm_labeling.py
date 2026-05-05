from __future__ import annotations

from cryptograph.llm_labeling import assess_pqc, simulate_label


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
