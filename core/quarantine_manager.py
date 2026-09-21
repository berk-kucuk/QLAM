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
        # 0700: the store holds live malware. The per-file 0o000 below is set
        # after the move, so there is a moment where the sample still carries
        # its original mode — possibly executable. A directory nothing else can
        # enter closes that window instead of racing it.
        try:
            os.chmod(QUARANTINE_DIR, 0o700)
        except OSError:
            pass
        self._index: list[QuarantinedFile] = []
        self._load_index()

    @staticmethod
    def _in_store(path: str) -> bool:
        """True if `path` really is one of our quarantined files.

        index.json is an ordinary file in the user's home, so its contents are
        input, not fact. Every path taken from it is checked back against the
        store before anything is moved or deleted — otherwise an edited index
        turns "restore" into "move this arbitrary file wherever I say" and
        "delete" into "unlink this arbitrary file". Harmless while Qlam runs as
        the user who owns both, and a real hole the first time any of this runs
        elevated, which is not a bet worth carrying.
        """
        try:
            root = os.path.realpath(QUARANTINE_DIR)
            target = os.path.realpath(path)
        except OSError:
            return False
        # Compare on a path boundary, never as a string prefix.
        return target.startswith(root + os.sep)

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
        if not self._in_store(entry.quarantine_path):
            return False
        if not os.path.isabs(entry.original_path):
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
        if not self._in_store(entry.quarantine_path):
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
        # Write-and-rename: opening the real file truncates it first, so a
        # crash mid-write left an index that named none of the files sitting in
        # the store — every quarantined sample orphaned, with no way back to
        # where it came from.
        tmp = QUARANTINE_INDEX.with_suffix(".tmp")
        try:
            with open(tmp, "w") as f:
                json.dump([e.to_dict() for e in self._index], f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, QUARANTINE_INDEX)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
