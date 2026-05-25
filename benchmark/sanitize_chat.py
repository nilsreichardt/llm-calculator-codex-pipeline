#!/usr/bin/env python3
"""Sanitize chat/session logs before sharing them.

By default this writes a privacy-friendlier transcript JSONL containing only
user and assistant messages. Use ``--mode jsonl`` to preserve the original JSONL
record structure while redacting sensitive fields.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


HOME = str(Path.home())

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (PRIVATE_KEY_RE, "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b"), "sk-[REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github_pat_[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "gh_[REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_API_KEY]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}\b"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"\bssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]+(?:\s+\S+)?"), "[REDACTED_SSH_PUBLIC_KEY]"),
    (re.compile(r"\bgAAAAA[A-Za-z0-9_-]{40,}={0,2}\b"), "[REDACTED_ENCRYPTED_CONTENT]"),
]

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key)"
    r"[A-Za-z0-9_.-]*)\s*([:=])\s*([\"']?)([^\s,\"';}\])]+)\3"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)

REDACTED_VALUE_KEYS = {
    "base_instructions",
    "developer_instructions",
    "dynamic_tools",
    "encrypted_content",
    "git",
    "rate_limits",
    "credits",
    "permission_profile",
    "repository_url",
    "sandbox_policy",
    "timezone",
    "collaboration_mode",
    "truncation_policy",
}

TIMESTAMP_KEYS = {"timestamp", "started_at", "completed_at", "current_date"}

DROP_EVENT_TYPES = {"token_count"}
DROP_RESPONSE_TYPES = {"reasoning"}


def redact_paths(text: str) -> str:
    """Remove local user-identifying path components."""
    if HOME:
        text = text.replace(HOME, "~")
    text = re.sub(r"/Users/[^/\"'\s]+", "/Users/[USER]", text)
    text = re.sub(r"/home/[^/\"'\s]+", "/home/[USER]", text)
    text = re.sub(r"/var/folders/[^\"'\s]+", "/var/folders/[REDACTED]", text)
    text = re.sub(r"[A-Za-z]:\\Users\\[^\\\"'\s]+", r"C:\\Users\\[USER]", text)
    return text


def redact_text(text: str, *, keep_timestamps: bool) -> str:
    """Redact common secrets and personal identifiers from free-form text."""
    text = redact_paths(text)
    text = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    for pattern, replacement in REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = IP_RE.sub("[REDACTED_IP]", text)
    text = UUID_RE.sub("[REDACTED_ID]", text)
    if not keep_timestamps:
        text = ISO_TIMESTAMP_RE.sub("[REDACTED_TIMESTAMP]", text)
    return text


def sanitize_json(value: Any, *, keep_timestamps: bool) -> Any:
    """Recursively sanitize a JSON-compatible value."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            clean_key = redact_text(str(key), keep_timestamps=keep_timestamps)
            if key in REDACTED_VALUE_KEYS:
                sanitized[clean_key] = f"[REDACTED_{key.upper()}]"
            elif key in TIMESTAMP_KEYS and not keep_timestamps:
                sanitized[clean_key] = "[REDACTED_TIMESTAMP]"
            else:
                sanitized[clean_key] = sanitize_json(item, keep_timestamps=keep_timestamps)
        return sanitized
    if isinstance(value, list):
        return [sanitize_json(item, keep_timestamps=keep_timestamps) for item in value]
    if isinstance(value, str):
        return redact_text(value, keep_timestamps=keep_timestamps)
    return value


def parse_jsonl(path: Path) -> list[dict[str, Any]] | None:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                return None
            if not isinstance(value, dict):
                raise SystemExit(f"{path}:{line_number}: expected each JSONL record to be an object")
            records.append(value)
    return records


def message_text(content: Any, *, keep_timestamps: bool) -> str:
    if isinstance(content, str):
        return redact_text(content, keep_timestamps=keep_timestamps)
    if isinstance(content, list):
        pieces: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text") or item.get("output_text")
                if isinstance(text, str):
                    pieces.append(text)
            elif isinstance(item, str):
                pieces.append(item)
        return redact_text("\n".join(piece for piece in pieces if piece), keep_timestamps=keep_timestamps)
    return redact_text(str(content), keep_timestamps=keep_timestamps)


def is_environment_context(text: str) -> bool:
    stripped = text.strip()
    return stripped.startswith("<environment_context>") and stripped.endswith("</environment_context>")


def transcript_records(
    records: list[dict[str, Any]],
    *,
    keep_timestamps: bool,
    include_environment: bool,
) -> list[dict[str, str]]:
    transcript: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for record in records:
        timestamp = record.get("timestamp")
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue

        role: str | None = None
        text: str | None = None

        if record.get("type") == "response_item" and payload.get("type") == "message":
            role_value = payload.get("role")
            if role_value in {"user", "assistant"}:
                role = role_value
                text = message_text(payload.get("content"), keep_timestamps=keep_timestamps)
        elif record.get("type") == "event_msg" and payload.get("type") == "agent_message":
            role = "assistant"
            text = message_text(payload.get("message"), keep_timestamps=keep_timestamps)

        if role is None or text is None or not text.strip():
            continue
        if role == "user" and not include_environment and is_environment_context(text):
            continue

        dedupe_key = (role, text)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        item = {"role": role, "content": text}
        if keep_timestamps and isinstance(timestamp, str):
            item["timestamp"] = redact_text(timestamp, keep_timestamps=True)
        transcript.append(item)

    return transcript


def sanitized_jsonl_records(records: list[dict[str, Any]], *, keep_timestamps: bool) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for record in records:
        payload = record.get("payload")
        if isinstance(payload, dict):
            if record.get("type") == "event_msg" and payload.get("type") in DROP_EVENT_TYPES:
                continue
            if record.get("type") == "response_item" and payload.get("type") in DROP_RESPONSE_TYPES:
                continue
        clean_record = sanitize_json(record, keep_timestamps=keep_timestamps)
        clean_payload = clean_record.get("payload") if isinstance(clean_record, dict) else None
        if (
            isinstance(clean_payload, dict)
            and clean_record.get("type") == "response_item"
            and clean_payload.get("type") == "message"
            and clean_payload.get("role") in {"developer", "system"}
        ):
            clean_payload["content"] = "[REDACTED_INTERNAL_MESSAGE]"
        elif (
            isinstance(payload, dict)
            and isinstance(clean_payload, dict)
            and clean_record.get("type") == "response_item"
            and clean_payload.get("type") == "message"
            and clean_payload.get("role") == "user"
            and is_environment_context(message_text(payload.get("content"), keep_timestamps=keep_timestamps))
        ):
            clean_payload["content"] = "[REDACTED_ENVIRONMENT_CONTEXT]"
        elif (
            isinstance(payload, dict)
            and isinstance(clean_payload, dict)
            and clean_record.get("type") == "event_msg"
            and clean_payload.get("type") == "user_message"
            and is_environment_context(message_text(payload.get("message"), keep_timestamps=keep_timestamps))
        ):
            clean_payload["message"] = "[REDACTED_ENVIRONMENT_CONTEXT]"
        sanitized.append(clean_record)
    return sanitized


def write_jsonl(records: list[dict[str, Any]], output: Path | None) -> None:
    handle = output.open("w", encoding="utf-8") if output else sys.stdout
    try:
        for record in records:
            print(json.dumps(record, ensure_ascii=False, sort_keys=False), file=handle)
    finally:
        if output:
            handle.close()


def write_text(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a privacy-friendlier version of a chat/session file.")
    parser.add_argument("chat_file", type=Path, help="Path to the chat file to sanitize.")
    parser.add_argument("-o", "--output", type=Path, help="Write sanitized output to this file. Defaults to stdout.")
    parser.add_argument(
        "--mode",
        choices=("transcript", "jsonl"),
        default="transcript",
        help="transcript keeps only user/assistant messages; jsonl preserves sanitized JSONL records.",
    )
    parser.add_argument(
        "--keep-timestamps",
        action="store_true",
        help="Keep timestamps instead of replacing them with [REDACTED_TIMESTAMP].",
    )
    parser.add_argument(
        "--include-environment",
        action="store_true",
        help="Include environment-context user records in transcript mode.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    chat_file: Path = args.chat_file
    if not chat_file.exists():
        raise SystemExit(f"Input file does not exist: {chat_file}")
    if not chat_file.is_file():
        raise SystemExit(f"Input path is not a file: {chat_file}")

    records = parse_jsonl(chat_file)
    if records is None:
        text = chat_file.read_text(encoding="utf-8")
        write_text(redact_text(text, keep_timestamps=args.keep_timestamps), args.output)
        return 0

    if args.mode == "transcript":
        output_records = transcript_records(
            records,
            keep_timestamps=args.keep_timestamps,
            include_environment=args.include_environment,
        )
    else:
        output_records = sanitized_jsonl_records(records, keep_timestamps=args.keep_timestamps)
    write_jsonl(output_records, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
