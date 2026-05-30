import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4


QUARANTINE_DIR = Path.home() / ".local" / "share" / "Qlam" / "quarantine"
QUARANTINE_INDEX = QUARANTINE_DIR / "index.json"


class QuarantinedFile:
    def __init__(self, qid: str, original_path: str, threat: str,
                 quarantine_path: str, timestamp: str):
        self.id = qid
        self.original_path = original_path
        self.threat = threat
        self.quarantine_path = quarantine_path
        self.timestamp = timestamp
        self.filename = os.path.basename(original_path)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "original_path": self.original_path,
            "threat": self.threat,
            "quarantine_path": self.quarantine_path,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "QuarantinedFile":
        return cls(
            d["id"], d["original_path"], d["threat"],
            d["quarantine_path"], d["timestamp"]
        )


class QuarantineManager:
    def __init__(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        self._index: list[QuarantinedFile] = []
        self._load_index()

    def quarantine_file(self, original_path: str, threat: str) -> QuarantinedFile | None:
        try:
            qid = str(uuid4())
            dest = QUARANTINE_DIR / f"{qid}.quar"
            shutil.move(original_path, str(dest))
            # Restrict permissions so the file can't be executed
            os.chmod(str(dest), 0o000)
            entry = QuarantinedFile(
                qid, original_path, threat,
                str(dest), datetime.now().isoformat()
            )
            self._index.append(entry)
            self._save_index()
            return entry
        except Exception:
            return None

    def restore_file(self, qid: str) -> bool:
        entry = self._find(qid)
        if entry is None:
            return False
        try:
            os.chmod(entry.quarantine_path, 0o644)
            dest_dir = os.path.dirname(entry.original_path)
            os.makedirs(dest_dir, exist_ok=True)
            shutil.move(entry.quarantine_path, entry.original_path)
            self._index.remove(entry)
            self._save_index()
            return True
        except Exception:
            return False

    def delete_file(self, qid: str) -> bool:
        entry = self._find(qid)
        if entry is None:
            return False
        try:
            if os.path.exists(entry.quarantine_path):
                os.chmod(entry.quarantine_path, 0o644)
                os.remove(entry.quarantine_path)
            self._index.remove(entry)
            self._save_index()
            return True
        except Exception:
            return False

    def delete_all(self) -> int:
        count = 0
        for entry in list(self._index):
            if self.delete_file(entry.id):
                count += 1
        return count

    def list_files(self) -> list[QuarantinedFile]:
        return list(self._index)

    def count(self) -> int:
        return len(self._index)

    # ── Persistence ───────────────────────────────────────────────────────

    def _find(self, qid: str) -> QuarantinedFile | None:
        for entry in self._index:
            if entry.id == qid:
                return entry
        return None

    def _load_index(self):
        if not QUARANTINE_INDEX.exists():
            self._index = []
            return
        try:
            with open(QUARANTINE_INDEX) as f:
                data = json.load(f)
            self._index = [QuarantinedFile.from_dict(d) for d in data]
            # Remove entries whose quarantine file no longer exists
            self._index = [e for e in self._index if os.path.exists(e.quarantine_path)]
        except Exception:
            self._index = []

    def _save_index(self):
        try:
            with open(QUARANTINE_INDEX, "w") as f:
                json.dump([e.to_dict() for e in self._index], f, indent=2)
        except Exception:
            pass
