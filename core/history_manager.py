import json
from datetime import datetime
from pathlib import Path
from uuid import uuid4


HISTORY_FILE = Path.home() / ".local" / "share" / "Qlam" / "history.json"


class ScanRecord:
    def __init__(self, record_id: str, scan_type: str, targets: list[str],
                 total_files: int, infected_files: int, duration: float,
                 timestamp: str, threats: list[dict]):
        self.id = record_id
        self.scan_type = scan_type        # "quick", "full", "custom"
        self.targets = targets
        self.total_files = total_files
        self.infected_files = infected_files
        self.duration = duration
        self.timestamp = timestamp
        self.threats = threats            # [{"path": ..., "threat": ...}]

    @property
    def timestamp_dt(self) -> datetime:
        try:
            return datetime.fromisoformat(self.timestamp)
        except Exception:
            return datetime.now()

    @property
    def status(self) -> str:
        if self.infected_files > 0:
            return "Threats Found"
        return "Clean"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "targets": self.targets,
            "total_files": self.total_files,
            "infected_files": self.infected_files,
            "duration": self.duration,
            "timestamp": self.timestamp,
            "threats": self.threats,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanRecord":
        return cls(
            d.get("id", str(uuid4())),
            d.get("scan_type", "custom"),
            d.get("targets", []),
            d.get("total_files", 0),
            d.get("infected_files", 0),
            d.get("duration", 0.0),
            d.get("timestamp", datetime.now().isoformat()),
            d.get("threats", []),
        )


class HistoryManager:
    MAX_RECORDS = 500

    def __init__(self):
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[ScanRecord] = []
        self._load()

    def add_record(self, scan_type: str, targets: list[str],
                   total_files: int, infected_files: int,
                   duration: float, threats: list[dict]) -> ScanRecord:
        record = ScanRecord(
            record_id=str(uuid4()),
            scan_type=scan_type,
            targets=targets,
            total_files=total_files,
            infected_files=infected_files,
            duration=duration,
            timestamp=datetime.now().isoformat(),
            threats=threats,
        )
        self._records.insert(0, record)
        if len(self._records) > self.MAX_RECORDS:
            self._records = self._records[:self.MAX_RECORDS]
        self._save()
        return record

    def get_records(self, limit: int = 100) -> list[ScanRecord]:
        return self._records[:limit]

    def clear(self):
        self._records = []
        self._save()

    def total_scans(self) -> int:
        return len(self._records)

    def total_threats(self) -> int:
        return sum(r.infected_files for r in self._records)

    def last_scan(self) -> ScanRecord | None:
        return self._records[0] if self._records else None

    def _load(self):
        if not HISTORY_FILE.exists():
            return
        try:
            with open(HISTORY_FILE) as f:
                data = json.load(f)
            self._records = [ScanRecord.from_dict(d) for d in data]
        except Exception:
            self._records = []

    def _save(self):
        try:
            with open(HISTORY_FILE, "w") as f:
                json.dump([r.to_dict() for r in self._records], f, indent=2)
        except Exception:
            pass
