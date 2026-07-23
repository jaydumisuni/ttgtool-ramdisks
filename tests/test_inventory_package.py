from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "inventory_package", ROOT / "scripts" / "inventory_package.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InventoryPackageTests(unittest.TestCase):
    def _zip(self, entries: dict[str, bytes]) -> Path:
        root = Path(tempfile.mkdtemp(prefix="ttg-ramdisk-inventory-"))
        path = root / "package.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        return path

    def test_inventory_hashes_and_classifies_without_extracting(self) -> None:
        path = self._zip(
            {
                "bin/gaster": b"gaster-fixture",
                "assets/iBSS.img4": b"ibss-fixture",
                "assets/iBEC.img4": b"ibec-fixture",
                "assets/ramdisk.img4": b"ramdisk-fixture",
                "assets/devicetree.img4": b"devicetree-fixture",
                "assets/kernelcache.img4": b"kernel-fixture",
            }
        )
        result = MODULE.inventory(path)
        roles = {item["role"] for item in result["classified_assets"]}
        self.assertEqual(result["schema_version"], "tgcheckm8.package-inventory.v1")
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["extraction_performed"])
        self.assertIn("gaster_executable", roles)
        self.assertIn("ramdisk", roles)
        self.assertIn("kernelcache", roles)
        self.assertEqual(len(result["archive_sha256"]), 64)

    def test_parent_directory_member_is_rejected(self) -> None:
        path = self._zip({"../ramdisk.img4": b"bad"})
        with self.assertRaises(ValueError):
            MODULE.inventory(path)

    def test_duplicate_casefolded_path_is_rejected(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="ttg-ramdisk-inventory-"))
        path = root / "package.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("assets/iBSS.img4", b"one")
            archive.writestr("ASSETS/IBSS.IMG4", b"two")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        with self.assertRaises(ValueError):
            MODULE.inventory(path)

    def test_symbolic_link_member_is_rejected(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="ttg-ramdisk-inventory-"))
        path = root / "package.zip"
        info = zipfile.ZipInfo("assets/ramdisk.img4")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(info, "target")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        with self.assertRaises(ValueError):
            MODULE.inventory(path)

    def test_invalid_zip_is_rejected_by_cli(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="ttg-ramdisk-inventory-"))
        path = root / "bad.zip"
        path.write_bytes(b"not a zip")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        self.assertEqual(MODULE.main([str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
