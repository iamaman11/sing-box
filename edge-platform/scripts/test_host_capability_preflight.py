#!/usr/bin/env python3
"""Git-selected legacy and typed VM read-only capability regression tests."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
from urllib.error import HTTPError, URLError

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

    def test_host_worker_get_probe_is_never_a_signing_admission(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False

        class Opener:
            def __init__(self, code):
                self.code = code
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                self_url = ("https://sing-box-credentials-vm.sing-box-test.workers.dev"
                            "/v1/host/authorize")
                assert request.full_url == self_url
                assert request.get_method() == "GET"
                assert request.get_header("Cf-access-client-id") == "opaque-id"
                assert request.get_header("Cf-access-client-secret") == "opaque-secret"
                if isinstance(self.code, BaseException):
                    raise self.code
                return Response()

        url = "https://sing-box-credentials-vm.sing-box-test.workers.dev/v1/host/authorize"
        for code, expected in [
            (HTTPError(url, 404, "not found", {}, None),
             "GET_404_WORKER_OR_EDGE_NOT_POST_PROOF"),
            (HTTPError(url, 403, "forbidden", {}, None),
             "GET_403_ACCESS_OR_EDGE_DENIED"),
            (HTTPError(url, 401, "unauthorized", {}, None),
             "GET_401_ACCESS_UNPROVEN"),
            (URLError("offline"), "GET_TRANSPORT_UNPROVEN"),
        ]:
            with patch.object(capability, "build_opener", return_value=Opener(code)):
                self.assertEqual(capability.observe_worker_host_get_route(
                    "sing-box-credentials-vm", "sing-box-test",
                    "opaque-id", "opaque-secret"), expected)
        with patch.object(capability, "build_opener", return_value=Opener(200)):
            self.assertEqual(capability.observe_worker_host_get_route(
                "sing-box-credentials-vm", "sing-box-test",
                "opaque-id", "opaque-secret"),
                "UNEXPECTED_GET_SUCCESS_NOT_SIGNING_PROOF")
        self.assertEqual(capability.observe_worker_host_get_route(
            "bad.domain", "sing-box-test", "id", "secret"),
            "GIT_WORKER_IDENTITY_UNPROVEN")
        self.assertEqual(capability.observe_worker_host_get_route(
            "sing-box-credentials-vm", "sing-box-test", "", ""),
            "ACCESS_SERVICE_IDENTITY_UNAVAILABLE")

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
