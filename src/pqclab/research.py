"""Synthetic, isolated security experiments for the PQC research lab."""

from __future__ import annotations

import json
import platform
import re
import uuid
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from pqclab.backend import doctor, require_backend
from pqclab.crypto.fingerprints import (
    fingerprint_matches,
    hybrid_kem_public_key_fingerprint,
)
from pqclab.crypto.hybrid import (
    generate_hybrid_keypair,
    hybrid_decapsulate,
    hybrid_encapsulate,
)
from pqclab.crypto.hybrid_signatures import (
    generate_hybrid_signature_keypair,
    hybrid_sign,
    hybrid_verify,
)
from pqclab.crypto.streaming import (
    HEADER_BYTES,
    TAG_BYTES,
    decrypt_stream,
    encrypt_stream,
)
from pqclab.errors import BackendUnavailable, CryptoFailure, FormatError
from pqclab.fuzzing import malformed_stream_corpus, run_parser_smoke_corpus


@dataclass(frozen=True, slots=True)
class ResearchScenario:
    scenario_id: str
    title: str
    expected: str
    observed: str
    passed: bool


@dataclass(frozen=True, slots=True)
class SecurityResearchReport:
    run_id: str
    created_at: str
    python_version: str
    native_version: str
    wrapper_version: str
    scenarios: tuple[ResearchScenario, ...]

    @property
    def passed(self) -> bool:
        return bool(self.scenarios) and all(scenario.passed for scenario in self.scenarios)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "environment": {
                "python": self.python_version,
                "liboqs": self.native_version,
                "liboqs_python": self.wrapper_version,
            },
            "passed": self.passed,
            "scenario_count": len(self.scenarios),
            "scenarios": [asdict(scenario) for scenario in self.scenarios],
        }


@dataclass(frozen=True, slots=True)
class SecurityResearchOutput:
    directory: Path
    json_path: Path
    markdown_path: Path


def _scenario(
    scenario_id: str,
    title: str,
    expected: str,
    observed: str,
    passed: bool,
) -> ResearchScenario:
    return ResearchScenario(scenario_id, title, expected, observed, passed)


def _reorder_first_two_chunks(ciphertext: bytes) -> bytes:
    if len(ciphertext) < HEADER_BYTES:
        raise FormatError("Encrypted stream header is truncated.")
    header = ciphertext[:HEADER_BYTES]
    offset = HEADER_BYTES
    chunks: list[bytes] = []
    final_record = b""
    while offset < len(ciphertext):
        if offset + 4 > len(ciphertext):
            raise FormatError("Encrypted stream record length is truncated.")
        length = int.from_bytes(ciphertext[offset : offset + 4], "big")
        record_end = offset + 4 + (TAG_BYTES if length == 0 else length + TAG_BYTES)
        if record_end > len(ciphertext):
            raise FormatError("Encrypted stream record is truncated.")
        record = ciphertext[offset:record_end]
        if length == 0:
            final_record = record
            offset = record_end
            break
        chunks.append(record)
        offset = record_end
    if len(chunks) < 2 or not final_record or offset != len(ciphertext):
        raise FormatError("Encrypted stream does not contain two chunks and a final record.")
    return header + chunks[1] + chunks[0] + b"".join(chunks[2:]) + final_record


def run_security_research() -> SecurityResearchReport:
    """Run bounded attacks against synthetic ephemeral fixtures; never use caller key material."""
    backend = doctor()
    if backend.status != "ready":
        raise BackendUnavailable("Security research requires the pinned native backend.")
    require_backend()

    scenarios: list[ResearchScenario] = []

    # ML-KEM uses implicit rejection: a modified ciphertext must not reproduce the sender key.
    recipient = generate_hybrid_keypair()
    kem_ciphertext, sender_secret = hybrid_encapsulate(
        recipient.public_key, context=b"pqclab/research/ciphertext-tampering"
    )
    changed = bytearray(kem_ciphertext.kem_ciphertext)
    changed[0] ^= 0x01
    tampered = replace(kem_ciphertext, kem_ciphertext=bytes(changed))
    receiver_secret = hybrid_decapsulate(
        recipient, tampered, context=b"pqclab/research/ciphertext-tampering"
    )
    scenarios.append(
        _scenario(
            "ciphertext-tampering",
            "Tampered hybrid KEM ciphertext",
            "Tampering must not reproduce the sender's shared secret.",
            "Implicit rejection produced a different receiver secret."
            if receiver_secret != sender_secret
            else "Tampered ciphertext reproduced the sender secret.",
            receiver_secret != sender_secret,
        )
    )

    # Explicit suite and version checks prevent protocol downgrade.
    downgrade_rejections = 0
    for downgraded in (
        replace(kem_ciphertext, version=0),
        replace(kem_ciphertext, kem_algorithm="ML-KEM-512"),
    ):
        try:
            hybrid_decapsulate(recipient, downgraded)
        except FormatError:
            downgrade_rejections += 1
    scenarios.append(
        _scenario(
            "protocol-downgrade",
            "Protocol version and algorithm downgrade",
            "Unsupported versions and suite substitution must raise FormatError.",
            f"{downgrade_rejections}/2 downgrade attempts rejected."
            if downgrade_rejections == 2
            else f"Only {downgrade_rejections}/2 downgrade attempts rejected.",
            downgrade_rejections == 2,
        )
    )

    # Compare the intended fingerprint with a substituted key, then test whether its private key derives the same secret.
    intended = generate_hybrid_keypair()
    substituted = generate_hybrid_keypair()
    intended_fingerprint = hybrid_kem_public_key_fingerprint(intended.public_key)
    substituted_fingerprint = hybrid_kem_public_key_fingerprint(substituted.public_key)
    substitution_detected = not fingerprint_matches(intended_fingerprint, substituted_fingerprint)
    intended_ciphertext, intended_secret = hybrid_encapsulate(intended.public_key)
    substituted_secret = hybrid_decapsulate(substituted, intended_ciphertext)
    substitution_rejected = substitution_detected and substituted_secret != intended_secret
    scenarios.append(
        _scenario(
            "recipient-key-substitution",
            "Recipient public-key substitution",
            "A substituted recipient key must have a different fingerprint and fail key agreement.",
            "Fingerprint mismatch detected; substituted recipient derived a different secret."
            if substitution_rejected
            else "Recipient substitution was not detected.",
            substitution_rejected,
        )
    )

    # Both components are mandatory; removing either must make the hybrid signature invalid.
    signer = generate_hybrid_signature_keypair()
    message = b"synthetic security research fixture"
    signature = hybrid_sign(signer, message, context=b"pqclab/research/signature-stripping")
    pq_stripped = replace(signature, pq_signature=b"")
    classical_stripped = replace(signature, classical_signature=b"")
    pq_rejected = not hybrid_verify(
        signer.public_key, message, pq_stripped, context=b"pqclab/research/signature-stripping"
    )
    classical_rejected = not hybrid_verify(
        signer.public_key,
        message,
        classical_stripped,
        context=b"pqclab/research/signature-stripping",
    )
    scenarios.append(
        _scenario(
            "hybrid-signature-stripping",
            "Hybrid signature component stripping",
            "Verification must fail if either ML-DSA or ECDSA is absent.",
            f"PQ component rejected={pq_rejected}; classical component rejected={classical_rejected}.",
            pq_rejected and classical_rejected,
        )
    )

    stream_key = bytes.fromhex("102132435465768798a9bacbdcedfe0f00112233445566778899aabbccddeeff")
    payload = b"chunk-00:" + b"A" * 23 + b"chunk-01:" + b"B" * 23 + b"chunk-02:" + b"C" * 23
    encrypted = BytesIO()
    encrypt_stream(BytesIO(payload), encrypted, stream_key, chunk_size=32)
    stream_ciphertext = encrypted.getvalue()
    reordered = _reorder_first_two_chunks(stream_ciphertext)
    try:
        decrypt_stream(BytesIO(reordered), BytesIO(), stream_key)
    except (CryptoFailure, FormatError):
        reorder_rejected = True
    else:
        reorder_rejected = False
    scenarios.append(
        _scenario(
            "stream-chunk-reordering",
            "Encrypted chunk reordering",
            "Reordered authenticated records must fail authentication.",
            "Reordered records rejected."
            if reorder_rejected
            else "Reordered records were accepted.",
            reorder_rejected,
        )
    )

    try:
        decrypt_stream(BytesIO(stream_ciphertext[:-1]), BytesIO(), stream_key)
    except FormatError:
        truncation_rejected = True
    else:
        truncation_rejected = False
    scenarios.append(
        _scenario(
            "stream-truncation",
            "Authenticated final-record truncation",
            "A missing final authentication tag must reject the complete stream.",
            "Truncated final record rejected."
            if truncation_rejected
            else "Truncated final record was accepted.",
            truncation_rejected,
        )
    )

    corpus = malformed_stream_corpus()
    rejected_count = run_parser_smoke_corpus()
    scenarios.append(
        _scenario(
            "stream-parser-fuzz-corpus",
            "Bounded malformed-envelope parser corpus",
            "Every malformed corpus input must be rejected without an unhandled parser exception.",
            f"{rejected_count}/{len(corpus)} malformed inputs rejected; "
            "fuzz target caps input at 1 MiB and plaintext at 8 MiB.",
            rejected_count == len(corpus),
        )
    )

    return SecurityResearchReport(
        run_id=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
        created_at=datetime.now(UTC).isoformat(),
        python_version=platform.python_version(),
        native_version=backend.native_version or "",
        wrapper_version=backend.wrapper_version or "",
        scenarios=tuple(scenarios),
    )


def export_security_report(
    report: SecurityResearchReport,
    output_dir: str | Path,
) -> SecurityResearchOutput:
    """Write sanitized JSON and Markdown results to a new run-specific directory."""
    if not isinstance(report, SecurityResearchReport):
        raise FormatError("Security research report has an invalid type.")
    if (
        not isinstance(report.run_id, str)
        or re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", report.run_id) is None
    ):
        raise FormatError("Security research report has an invalid run identifier.")
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    run_dir = root / report.run_id
    run_dir.mkdir(exist_ok=False)
    json_path = run_dir / "research.json"
    markdown_path = run_dir / "research.md"

    json_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# PQC Security Research Results",
        "",
        f"- Run: `{report.run_id}`",
        f"- Created: {report.created_at}",
        f"- Python: {report.python_version}",
        f"- liboqs: {report.native_version}",
        f"- liboqs-python: {report.wrapper_version}",
        f"- Overall: {'PASS' if report.passed else 'FAIL'}",
        "",
        "| Scenario | Expected behavior | Observed behavior | Result |",
        "|---|---|---|---|",
    ]
    for scenario in report.scenarios:
        result = "PASS" if scenario.passed else "FAIL"
        lines.append(f"| {scenario.title} | {scenario.expected} | {scenario.observed} | {result} |")
    lines.extend(
        [
            "",
            (
                "All fixtures use newly generated ephemeral keys and synthetic messages. "
                "No caller keys, passphrases, plaintext files, or shared secrets are written to the report."
            ),
            "",
            "This is a research harness, not a production security certification or side-channel assessment.",
            "",
        ]
    )
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return SecurityResearchOutput(run_dir, json_path, markdown_path)
