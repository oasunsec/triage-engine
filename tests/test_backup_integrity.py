"""Backup regression coverage using isolated real SQLite databases."""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from scripts.backup_restore import create_backup, restore_backup, verify_backup


class BackupIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp_parent = Path(__file__).resolve().parents[1] / "runtime/temp/forensic-foundation-backup"
        self.temp_parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=self.temp_parent)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.connections = []
        for name in ("auth.db", "reviews.db", "jobs.db"):
            self.seed(name)

    def tearDown(self):
        for connection in self.connections:
            connection.close()
        self.temp.cleanup()
        try:
            self.temp_parent.rmdir()
        except OSError:
            pass

    def seed(self, name, wal=False):
        connection = sqlite3.connect(self.data / name)
        if wal:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE marker (value TEXT)")
        connection.execute("INSERT INTO marker VALUES (?)", (name,))
        connection.commit()
        if wal:
            self.connections.append(connection)
        else:
            connection.close()
        return connection

    def backup(self):
        return Path(create_backup(data_dir=self.data)["backup_path"])

    def rewrite(self, backup, mutate):
        path = backup / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        mutate(manifest)
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def assert_restore_rejected_unchanged(self, backup):
        before = {path.name: path.read_bytes() for path in self.data.glob("*.db")}
        with self.assertRaises((ValueError, FileNotFoundError)):
            restore_backup(backup, data_dir=self.data, service_stopped=True)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.data.glob("*.db")})

    def test_committed_active_wal_and_product_round_trip(self):
        writer = self.seed("product.db", wal=True)
        writer.execute("INSERT INTO marker VALUES ('committed WAL')")
        writer.commit()
        self.assertTrue((self.data / "product.db-wal").is_file())
        backup = self.backup()
        self.assertEqual(len(verify_backup(backup)["files"]), 4)
        with closing(sqlite3.connect(backup / "product.db")) as snapshot:
            self.assertEqual(snapshot.execute("SELECT value FROM marker").fetchall(), [("product.db",), ("committed WAL",)])
        writer.close()
        self.connections.remove(writer)
        # A stopped service can leave stale sidecars; these must not replay
        # against the restored snapshot.
        for suffix in ("-wal", "-shm", "-journal"):
            (self.data / ("product.db" + suffix)).write_bytes(b"stale")
        result = restore_backup(backup, data_dir=self.data, service_stopped=True)
        self.assertEqual(len(result["files"]), 4)
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse((self.data / ("product.db" + suffix)).exists())
        with closing(sqlite3.connect(self.data / "product.db")) as restored:
            self.assertEqual(restored.execute("SELECT value FROM marker").fetchall(), [("product.db",), ("committed WAL",)])
            self.assertEqual(restored.execute("PRAGMA integrity_check").fetchone(), ("ok",))

    def test_legacy_three_database_backup_and_restore(self):
        backup = self.backup()
        self.assertEqual(len(verify_backup(backup)["files"]), 3)
        with closing(sqlite3.connect(self.data / "auth.db")) as connection:
            connection.execute("UPDATE marker SET value='changed'")
            connection.commit()
        restored = restore_backup(backup, data_dir=self.data, service_stopped=True)
        self.assertEqual(len(restored["files"]), 3)
        with closing(sqlite3.connect(self.data / "auth.db")) as connection:
            self.assertEqual(connection.execute("SELECT value FROM marker").fetchone(), ("auth.db",))

    def test_restore_requires_stopped_service_acknowledgement(self):
        backup = self.backup()
        before = (self.data / "auth.db").read_bytes()
        with self.assertRaisesRegex(ValueError, "stopped service"):
            restore_backup(backup, data_dir=self.data)
        self.assertEqual((self.data / "auth.db").read_bytes(), before)

    def test_tampered_last_database_does_not_restore_earlier_database(self):
        backup = self.backup()
        with closing(sqlite3.connect(self.data / "auth.db")) as connection:
            connection.execute("UPDATE marker SET value='changed'")
            connection.commit()
        with (backup / "jobs.db").open("ab") as stream:
            stream.write(b"tampered")
        self.assert_restore_rejected_unchanged(backup)

    def test_unsafe_missing_duplicate_and_invalid_manifest_entries(self):
        mutations = [
            lambda m: m["files"][0].update(name="../auth.db"),
            lambda m: m["files"][0].update(name=str(self.data / "auth.db")),
            lambda m: m["files"][0].update(name="unexpected.db"),
            lambda m: m["files"].append(dict(m["files"][0])),
            lambda m: m["files"].pop(),
            lambda m: m["files"].append("invalid"),
            lambda m: m["files"][0].update(size_bytes=True),
            lambda m: m["files"][0].update(sha256="invalid"),
            lambda m: m.update(total_bytes=m["total_bytes"] + 1),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                backup = self.backup()
                self.rewrite(backup, mutate)
                self.assert_restore_rejected_unchanged(backup)

    def test_matching_checksum_cannot_hide_malformed_sqlite(self):
        backup = self.backup()
        malformed = b"not sqlite"
        (backup / "jobs.db").write_bytes(malformed)
        def mutate(manifest):
            entry = next(item for item in manifest["files"] if item["name"] == "jobs.db")
            entry.update(size_bytes=len(malformed), sha256=hashlib.sha256(malformed).hexdigest())
            manifest["total_bytes"] = sum(item["size_bytes"] for item in manifest["files"])
        self.rewrite(backup, mutate)
        self.assert_restore_rejected_unchanged(backup)

    def test_create_rejects_malformed_source_and_cleans_partial_backup(self):
        (self.data / "jobs.db").write_bytes(b"not sqlite")
        with self.assertRaises(sqlite3.DatabaseError):
            self.backup()
        self.assertEqual(list((self.data / "backups").iterdir()), [])

    def test_symlink_backup_file_is_rejected(self):
        backup = self.backup()
        (backup / "jobs.db").unlink()
        try:
            (backup / "jobs.db").symlink_to(self.data / "jobs.db")
        except OSError as exc:
            self.skipTest(f"Symlink creation unavailable: {exc}")
        self.assert_restore_rejected_unchanged(backup)

    def test_backup_sidecars_are_rejected(self):
        backup = self.backup()
        (backup / "jobs.db-wal").write_bytes(b"stale")
        self.assert_restore_rejected_unchanged(backup)


if __name__ == "__main__":
    unittest.main()
