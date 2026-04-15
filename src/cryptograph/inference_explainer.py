"""Explainability engine for cryptographic inference.

Explains how usage context, intent, and flow conclusions are derived
from code patterns and graph analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Explanation:
    """Explains how a field was derived."""

    value: Any
    method: str  # How we determined this value
    confidence: float  # 0.0-1.0 confidence in this determination
    evidence: list[str]  # Specific evidence supporting this


class InferenceExplainer:
    """Generates explanations for inferred fields."""

    @staticmethod
    def explain_usage_context(
        function: str | None,
        api_name: str,
        algorithm: str,
        primitive: str,
        context: dict[str, Any],
    ) -> Explanation:
        """Explain how we inferred the usage context.

        Common contexts:
        - authentication_flow: In login/auth function
        - data_protection: In encryption context
        - key_generation: Key derivation or generation
        - signature_verification: Digital signatures
        - random_number_generation: RNG
        """
        evidence: list[str] = []
        function_lower = (function or "").lower()
        scope = context.get("scope", {})
        file_lower = str(scope.get("file", "")).lower()
        call_chain_text = " ".join(scope.get("call_chain", [])).lower()
        api_lower = api_name.lower()
        combined = " ".join([function_lower, file_lower, call_chain_text, api_lower, algorithm.lower(), primitive.lower()])

        if any(token in combined for token in ["certificate", "cert", "x509", "csr"]):
            evidence.append("Certificate/X.509 signal from file, function, API, or algorithm")
            value = "certificate_generation" if any(token in combined for token in ["generate", "builder", "self_signed", "csr"]) else "certificate_management"
            return Explanation(
                value=value,
                method="multi_signal_context",
                confidence=0.92,
                evidence=evidence,
            )

        if primitive in {"asymmetric_key_generation", "symmetric_key_generation", "key_derivation"}:
            if any(token in combined for token in ["key", "derive", "kdf", "generate"]):
                evidence.append("Key-management primitive plus key/derive/generate context")
                return Explanation(
                    value="key_management",
                    method="primitive_and_context",
                    confidence=0.86,
                    evidence=evidence,
                )

        # Function name analysis
        if any(kw in function_lower for kw in ["auth", "login", "password", "hash"]):
            evidence.append("Function name contains authentication keyword")
            return Explanation(
                value="authentication_flow",
                method="function_name_pattern",
                confidence=0.85,
                evidence=evidence,
            )

        if any(kw in function_lower for kw in ["encrypt", "cipher", "encode"]):
            evidence.append("Function name contains encryption keyword")
            return Explanation(
                value="data_protection",
                method="function_name_pattern",
                confidence=0.9,
                evidence=evidence,
            )

        if any(kw in function_lower for kw in ["sign", "verify", "signature"]):
            signature_value = "signature_verification" if "verify" in function_lower else "signature_generation"
            evidence.append("Function name contains signature keyword")
            return Explanation(
                value=signature_value,
                method="function_name_pattern",
                confidence=0.9,
                evidence=evidence,
            )

        if any(kw in function_lower for kw in ["random", "generate", "seed", "nonce"]):
            evidence.append("Function name contains RNG keyword")
            return Explanation(
                value="random_number_generation",
                method="function_name_pattern",
                confidence=0.85,
                evidence=evidence,
            )

        # Primitive-based fallback
        primitive_contexts = {
            "symmetric_encryption": "data_protection",
            "asymmetric_encryption": "key_exchange",
            "key_derivation": "key_management",
            "message_authentication": "integrity_verification",
            "random_generation": "random_material_generation",
            "hash": "hashing",
            "certificate_management": "certificate_management",
        }

        if primitive in primitive_contexts:
            context_value = primitive_contexts[primitive]
            evidence.append(f"Derived from primitive type: {primitive}")
            return Explanation(
                value=context_value,
                method="primitive_classification",
                confidence=0.70,
                evidence=evidence,
            )

        return Explanation(
            value="general_cryptographic_operation",
            method="fallback",
            confidence=0.5,
            evidence=["No specific pattern detected"],
        )

    @staticmethod
    def explain_intent(
        algorithm: str,
        primitive: str,
        api_name: str,
        arguments: list[str],
        context: dict[str, Any],
    ) -> Explanation:
        """Explain what the cryptographic operation intends to do.

        Common intents:
        - create_encryption_key
        - derive_password_key
        - verify_data_integrity
        - create_random_material
        - sign_data
        - encrypt_data
        """
        evidence: list[str] = []

        # Algorithm-based intent
        api_lower = api_name.lower()
        context_text = " ".join(
            [
                str(context.get("scope", {}).get("function") or ""),
                str(context.get("scope", {}).get("file") or ""),
                " ".join(context.get("scope", {}).get("call_chain", [])),
                api_lower,
                algorithm.lower(),
                primitive.lower(),
            ]
        ).lower()

        if primitive == "certificate_management" or "certificatebuilder" in api_lower:
            evidence.append("X.509 certificate builder or certificate management primitive")
            return Explanation(
                value="build_certificate" if "builder" in api_lower else "manage_certificate_lifecycle",
                method="api_and_primitive",
                confidence=0.92,
                evidence=evidence,
            )

        if primitive in {"certificate_request", "certificate_attribute", "certificate_extension"}:
            evidence.append("Certificate lifecycle support primitive")
            return Explanation(
                value="manage_certificate_lifecycle",
                method="primitive_type",
                confidence=0.86,
                evidence=evidence,
            )

        if primitive == "key_serialization" or "serialization." in api_lower:
            evidence.append("Key or certificate serialization API")
            return Explanation(
                value="key_material_serialization",
                method="api_and_primitive",
                confidence=0.9,
                evidence=evidence,
            )

        if primitive in {"asymmetric_key_generation", "symmetric_key_generation"} and any(
            token in context_text for token in ["certificate", "cert", "x509", "csr"]
        ):
            evidence.append("Key generation occurs in certificate-related context")
            return Explanation(
                value="create_key_material",
                method="primitive_and_certificate_context",
                confidence=0.93,
                evidence=evidence,
            )

        if algorithm in ("PBKDF2", "Scrypt", "Argon2", "bcrypt"):
            evidence.append(f"{algorithm} is designed for password derivation")
            return Explanation(
                value="derive_password_key",
                method="algorithm_purpose",
                confidence=0.95,
                evidence=evidence,
            )

        if algorithm in ("HKDF", "KDF"):
            evidence.append("General-purpose key derivation function")
            return Explanation(
                value="derive_key_material",
                method="algorithm_purpose",
                confidence=0.9,
                evidence=evidence,
            )

        if primitive == "symmetric_encryption":
            evidence.append("Symmetric encryption primitive")
            return Explanation(
                value="encrypt_data",
                method="primitive_type",
                confidence=0.85,
                evidence=evidence,
            )

        if primitive in {"asymmetric_key_generation", "symmetric_key_generation"}:
            evidence.append("Key generation primitive")
            return Explanation(
                value="create_key_material",
                method="primitive_type",
                confidence=0.9,
                evidence=evidence,
            )

        if primitive == "random_generation":
            evidence.append("Random generation primitive")
            # Check if it's for key material
            signals = context.get("signals", {})
            if "salt" in str(arguments).lower() or "iv" in str(arguments).lower():
                evidence.append("Arguments suggest salt/IV generation")
                return Explanation(
                    value="create_iv_or_salt",
                    method="argument_analysis",
                    confidence=0.8,
                    evidence=evidence,
                )
            return Explanation(
                value="create_random_material",
                method="primitive_type",
                confidence=0.8,
                evidence=evidence,
            )

        if primitive == "message_authentication":
            evidence.append("Message authentication primitive (HMAC)")
            return Explanation(
                value="verify_data_integrity",
                method="primitive_type",
                confidence=0.85,
                evidence=evidence,
            )

        if primitive == "hash":
            evidence.append("Hash function primitive")
            return Explanation(
                value="compute_hash_digest",
                method="primitive_type",
                confidence=0.80,
                evidence=evidence,
            )

        # Fallback
        return Explanation(
            value="unspecified_cryptographic_operation",
            method="fallback",
            confidence=0.5,
            evidence=["Unable to determine specific intent"],
        )

    @staticmethod
    def explain_data_flow(
        api_name: str,
        arguments: list[str],
        context: dict[str, Any],
    ) -> Explanation:
        """Explain the data flow into and out of the cryptographic operation."""
        evidence: list[str] = []
        signals = context.get("signals", {})
        sources = signals.get("sources", [])
        flow = context.get("flow", {})

        # Determine input sources
        input_sources: list[str] = []
        for source in sources:
            classification = source.get("classification", "unknown")
            if classification in (
                "key_material",
                "user_input",
                "generated_random",
                "hardcoded_constant",
                "derived_from_kdf",
            ):
                if classification == "key_material" and flow.get("key_source") not in {
                    "function_parameter",
                    "local_assignment",
                    "hardcoded_constant",
                    "object_property",
                    "return_value",
                    "derived_value",
                    "external_input",
                }:
                    continue
                _append_unique(input_sources, classification)

        for field in ("key_source", "data_source", "iv_source", "nonce_source", "salt_source", "randomness_source"):
            source = flow.get(field)
            if source == "derived_from_kdf":
                _append_unique(input_sources, "derived_from_kdf")
            elif source in {"generated_random", "hardcoded_constant"}:
                _append_unique(input_sources, source)
            elif source == "external_input":
                _append_unique(input_sources, "user_input")

        for signal in signals.get("arguments", []):
            if signal.get("is_literal") and signal.get("role") in {"key", "data", "iv", "nonce", "salt"}:
                _append_unique(input_sources, "hardcoded_constant")

        if "hardcoded_constant" in input_sources:
            evidence.append("Cryptographic material may be hardcoded in source")

        if "user_input" in input_sources:
            evidence.append("User input flows to cryptographic operation")

        if "generated_random" in input_sources:
            evidence.append("Cryptographically generated random material used")

        # Determine output destinations
        sink = signals.get("sink") or {}
        sink_classification = sink.get("classification", "unknown")

        if sink_classification in ("file_output", "network_output", "database_output"):
            evidence.append(f"Output may flow to {sink_classification}")

        return Explanation(
            value={
                "input_sources": input_sources,
                "output_destination": sink_classification,
            },
            method="signal_flow_analysis",
            confidence=0.75,
            evidence=evidence,
        )

    @staticmethod
    def explain_derivation_path(
        call_chain: list[str],
        graph_context: dict[str, Any],
    ) -> Explanation:
        """Explain the derivation path in the call graph.

        Shows how data flows through function calls.
        """
        evidence: list[str] = []

        # Call chain depth
        if call_chain:
            evidence.append(f"Call chain depth: {len(call_chain)} function(s)")
            if len(call_chain) > 1:
                evidence.append(f"Root function: {call_chain[0]}")
                evidence.append(f"Cryptographic call in: {call_chain[-1]}")

        # Cross-function flow
        call_graph = graph_context.get("call_graph", {})
        callers = call_graph.get("callers", [])
        callees = call_graph.get("callees", [])

        if callers:
            evidence.append(f"Function called by: {len(callers)} caller(s)")
        if callees:
            evidence.append(f"Function calls: {len(callees)} other function(s)")

        # Interprocedural flow
        cross_function = len(callers) > 0 or len(callees) > 0
        if cross_function:
            evidence.append("Cross-function data flow detected")

        return Explanation(
            value={
                "call_depth": len(call_chain),
                "cross_function_flow": cross_function,
                "entry_point": call_chain[0] if call_chain else None,
            },
            method="call_graph_analysis",
            confidence=0.9,
            evidence=evidence,
        )


def build_inference_explanations(
    function: str | None,
    api_name: str,
    algorithm: str,
    primitive: str,
    arguments: list[str],
    context: dict[str, Any],
) -> dict[str, Explanation]:
    """Build all inference explanations for an asset.

    Returns:
        Dict mapping field name to Explanation object.
    """
    explainer = InferenceExplainer()

    return {
        "usage_context": explainer.explain_usage_context(function, api_name, algorithm, primitive, context),
        "intent": explainer.explain_intent(algorithm, primitive, api_name, arguments, context),
        "data_flow": explainer.explain_data_flow(api_name, arguments, context),
        "derivation_path": explainer.explain_derivation_path(
            context.get("scope", {}).get("call_chain", []),
            context.get("graph", {}),
        ),
    }


def explanation_summary(exp: Explanation) -> dict:
    """Convert Explanation to JSON-serializable dict."""
    return {
        "value": str(exp.value) if not isinstance(exp.value, (str, bool, int, float, list, dict)) else exp.value,
        "method": exp.method,
        "confidence": round(exp.confidence, 3),
        "evidence": exp.evidence,
    }


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)
