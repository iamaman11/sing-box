#!/usr/bin/env python3
"""Git-selected legacy and typed VM read-only capability regression tests."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

import host_capability_preflight as capability


class TestHostCapabilitySelector(TestCase):
    def test_typed_vm_selects_exact_git_path_without_legacy_json(self):
        with TemporaryDirectory() as root:
            previous = Path.cwd()
            try:
                os.chdir(root)
                spec = Path("infra/hosts/specs/acceptance-2.textproto")
                spec.parent.mkdir(parents=True)
                spec.write_text('schema_version: 1\nmachine_id: "acceptance-2"\n')
                self.assertTrue(capability.target_machine(str(spec), "acceptance-2"))
                self.assertFalse(capability.target_machine(str(spec), "unrelated"))
                self.assertFalse(capability.target_machine("../" + str(spec), "acceptance-2"))
                spec.unlink()
                spec.symlink_to(Path(root) / "unrelated")
                self.assertFalse(capability.target_machine(str(spec), "acceptance-2"))
            finally:
                os.chdir(previous)

    def test_legacy_json_retains_read_only_provider_scope(self):
        with TemporaryDirectory() as root:
            previous = Path.cwd()
            try:
                os.chdir(root)
                app = Path("infra/application/disposable-acceptance.json")
                provider = Path("infra/vultr/application-acceptance.json")
                app.parent.mkdir(parents=True)
                provider.parent.mkdir(parents=True)
                app.write_text(json.dumps({
                    "schema": 2, "machine_id": "acceptance-1",
                    "vultr_spec_path": str(provider)
                }))
                provider.write_text(json.dumps({
                    "schema": 1, "machines": [{"id": "acceptance-1"}]
                }))
                self.assertTrue(capability.target_machine(str(app), "acceptance-1"))
                self.assertFalse(capability.target_machine(str(app), "acceptance-2"))
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    main()
