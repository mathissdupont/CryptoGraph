from __future__ import annotations

from cryptograph.cyclonedx_cbom import convert_to_cyclonedx_cbom


def test_convert_custom_cbom_to_cyclonedx_hybrid_preserves_analysis() -> None:
    custom_cbom = {
        "spec_version": "1.0",
        "metadata": {
            "tool": "CryptoGraph",
            "generated_at": "2026-04-16T12:00:00+00:00",
            "source": "samples",
            "backend": "fraunhofer-cpg",
            "run_id": "run-1",
            "source_language": "python",
        },
        "cryptographic_assets": [
            {
                "asset_id": "crypto-aes-1",
                "crypto_metadata": {
                    "algorithm": "AES",
                    "primitive": "symmetric_encryption",
                    "mode": "GCM",
                    "provider": "cryptography",
                    "key_size": 256,
                },
                "usage": {"operation": "encryption"},
                "context": {
                    "file": "auth_flow.py",
                    "function": "auth_flow.encrypt_auth_token",
                    "call_chain": ["auth_flow.login", "auth_flow.encrypt_auth_token"],
                    "usage_context": "authentication_flow",
                },
                "flow": {
                    "key_source": "function_parameter",
                    "data_source": "classified_user_input",
                    "iv_source": "generated_random",
                    "nonce_source": None,
                    "salt_source": None,
                },
                "risk": {"level": "low", "tags": ["aead"], "confidence": 0.91},
                "rules": [{"id": "AES_GCM_OK", "message": "AEAD mode"}],
                "inference": {"intent": {"value": "protect_token", "confidence": 0.8}},
                "graph_context": {"call_depth": 2, "edge_kinds": ["CALLS"]},
                "evidence": {
                    "summary": {"api_call": "Cipher", "arguments": ["algorithms.AES(key)", "modes.GCM(iv)"]},
                    "debug": {"raw_node_id": "heavy-debug-should-not-leak"},
                },
            }
        ],
    }

    cyclonedx = convert_to_cyclonedx_cbom(custom_cbom)

    assert cyclonedx["bomFormat"] == "CycloneDX"
    assert cyclonedx["specVersion"] == "1.5"
    assert cyclonedx["version"] == 1
    assert cyclonedx["metadata"]["component"] == {
        "type": "application",
        "name": "cryptograph-analysis",
        "version": "1.0",
    }

    asset = next(component for component in cyclonedx["components"] if component["bom-ref"] == "crypto-aes-1")
    assert asset["type"] == "cryptographic-asset"
    assert asset["name"] == "AES"
    assert asset["cryptoProperties"] == {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": "symmetric_encryption",
            "parameterSetIdentifier": "GCM",
            "cryptoFunctions": ["encrypt"],
        },
    }
    assert asset["analysis"]["context"]["function"] == "auth_flow.encrypt_auth_token"
    assert asset["analysis"]["flow"]["data_source"] == "classified_user_input"
    assert asset["analysis"]["risk"] == {"level": "low", "confidence": 0.91, "tags": ["aead"]}
    assert asset["analysis"]["rules"][0]["id"] == "AES_GCM_OK"
    assert asset["analysis"]["inference"]["intent"]["value"] == "protect_token"
    assert asset["analysis"]["graph_context"]["call_depth"] == 2
    assert asset["analysis"]["evidence"] == {
        "summary": {"api_call": "Cipher", "arguments": ["algorithms.AES(key)", "modes.GCM(iv)"]}
    }
    assert "debug" not in asset["analysis"]["evidence"]

    provider = next(component for component in cyclonedx["components"] if component["bom-ref"] == "crypto-provider:cryptography")
    assert provider["type"] == "library"
    assert {"ref": "crypto-aes-1", "dependsOn": ["crypto-provider:cryptography"]} in cyclonedx["dependencies"]


def test_converter_omits_optional_unknown_parameter_set() -> None:
    cyclonedx = convert_to_cyclonedx_cbom(
        {
            "metadata": {"tool": "CryptoGraph", "source": "samples"},
            "cryptographic_assets": [
                {
                    "asset_id": "crypto-rng-1",
                    "crypto_metadata": {
                        "algorithm": "CSPRNG",
                        "primitive": "random_generation",
                        "mode": None,
                        "key_size": None,
                        "provider": "python-stdlib",
                    },
                    "usage": {"operation": "random_generation"},
                    "risk": {"level": "low", "confidence": 0.7, "tags": []},
                    "evidence": {"summary": {"api_call": "os.urandom"}},
                }
            ],
        }
    )

    asset = next(component for component in cyclonedx["components"] if component["bom-ref"] == "crypto-rng-1")
    algorithm_properties = asset["cryptoProperties"]["algorithmProperties"]
    assert algorithm_properties["primitive"] == "random_generation"
    assert algorithm_properties["cryptoFunctions"] == ["generate"]
    assert "parameterSetIdentifier" not in algorithm_properties
    assert "unknown" not in str(cyclonedx)


def test_converter_prunes_noisy_unknown_analysis_placeholders() -> None:
    cyclonedx = convert_to_cyclonedx_cbom(
        {
            "cryptographic_assets": [
                {
                    "asset_id": "crypto-placeholder-1",
                    "crypto_metadata": {"algorithm": "CSPRNG", "primitive": "random_generation"},
                    "usage": {"operation": "random_generation"},
                    "context": {"file": "unknown_file", "function": "unknown_function", "line": 10},
                    "flow": {"key_source": "unknown", "randomness_source": "generated_random"},
                    "risk": {"level": "low", "confidence": 0.7, "tags": []},
                    "evidence": {
                        "summary": {
                            "api_call": "os.urandom",
                            "resolved_name": "UNKNOWN.urandom",
                            "callee": "os.urandom",
                        }
                    },
                }
            ]
        }
    )

    asset = next(component for component in cyclonedx["components"] if component["bom-ref"] == "crypto-placeholder-1")
    assert asset["analysis"]["context"] == {"line": 10}
    assert asset["analysis"]["flow"] == {"randomness_source": "generated_random"}
    assert asset["analysis"]["evidence"]["summary"] == {
        "api_call": "os.urandom",
        "callee": "os.urandom",
    }
