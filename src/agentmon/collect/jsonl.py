"""Append-only JSON Lines source.

The cursor is (device, inode, offset). A new inode or a file shorter than the
offset means rotation or truncation: the file is replayed from the start, which
is safe because ingestion is idempotent by event id.

A digest of the first bytes is kept too, so a copy-truncate rotation that has
already grown past the old offset is still recognised.

A partial last line is left for the next cycle. A line longer than
``max_line_bytes`` is skipped up to its newline and reported, so one bad record
can never block the source.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .base import Ingestor, SourceReport

HEAD_BYTES = 256


def _head(handle: BinaryIO, length: int) -> str:
    handle.seek(0)
    return hashlib.sha256(handle.read(length)).hexdigest()


@dataclass(frozen=True, slots=True)
class JsonlSourceConfig:
    name: str
    path: Path
    agents: frozenset[str]
    max_line_bytes: int = 65_536
    max_bytes_per_cycle: int = 8 * 1024 * 1024


class JsonlSource:
    kind = "jsonl"

    def __init__(self, config: JsonlSourceConfig) -> None:
        self.config = config
        self.name = config.name

    def collect(self, ingestor: Ingestor) -> SourceReport:
        cfg = self.config
        report = SourceReport(self.name, self.kind, details={"agents": sorted(cfg.agents)})
        state = ingestor.store.cursor(self.name)
        try:
            stat = os.stat(cfg.path)
        except OSError as exc:
            code = "missing" if exc.errno == errno.ENOENT else "unreadable"
            return report.unavailable(code, "telemetry file cannot be read")

        identity = f"{stat.st_dev}:{stat.st_ino}"
        rejections: Counter[str] = Counter()
        budget = cfg.max_bytes_per_cycle
        try:
            with open(cfg.path, "rb") as handle:
                head_length = int(state.get("head_length", 0))
                same_file = (
                    state.get("identity") == identity
                    and int(state.get("offset", 0)) <= stat.st_size
                    and _head(handle, head_length) == state.get("head")
                )
                offset = int(state.get("offset", 0)) if same_file else 0
                skipping = bool(state.get("skipping")) if same_file else False
                if state and not same_file:
                    report.details["rewound"] = True
                head_length = min(HEAD_BYTES, stat.st_size)
                head = _head(handle, head_length)
                handle.seek(offset)
                while budget > 0:
                    line = handle.readline(cfg.max_line_bytes + 1)
                    if not line:
                        break
                    complete = line.endswith(b"\n")
                    if skipping:
                        skipping = not complete
                    elif not complete and len(line) <= cfg.max_line_bytes:
                        break  # a writer is still appending this record
                    elif not complete:
                        rejections["oversized"] += 1
                        skipping = True
                    elif line.strip():
                        try:
                            raw = json.loads(line)
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            rejections["invalid_json"] += 1
                        else:
                            ingestor.ingest(raw, report, cfg.agents, rejections)
                    offset = handle.tell()
                    budget -= len(line)
        except OSError:
            return report.unavailable("unreadable", "telemetry file cannot be read")

        Ingestor.flush_rejections(report, rejections)
        total = int(state.get("rejected_total", 0)) + sum(rejections.values())
        ingestor.store.set_cursor(
            self.name,
            {
                "identity": identity,
                "offset": offset,
                "skipping": skipping,
                "head": head,
                "head_length": head_length,
                "rejected_total": total,
            },
        )
        report.details.update({"lagBytes": max(0, stat.st_size - offset), "rejectedTotal": total})
        return report
