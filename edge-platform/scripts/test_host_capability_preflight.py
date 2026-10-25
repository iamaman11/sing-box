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
import host_diagnostic_summary as summary


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
            headers = {}
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
             "GET_403_EDGE_OR_UNVERIFIED_WORKER_DENIED"),
            (HTTPError(url, 403, "forbidden", {
                "X-Host-Authorization-Scope": "READ_ONLY_NO_MUTATION",
                "X-Host-Authorization-Reason": "JWT_MISSING",
            }, None), "GET_403_WORKER_JWT_MISSING"),
            (HTTPError(url, 403, "forbidden", {
                "X-Host-Authorization-Scope": "READ_ONLY_NO_MUTATION",
                "X-Host-Authorization-Reason": "JWT_JWKS_FETCH_SAME_ZONE_BLOCKED",
            }, None), "GET_403_WORKER_JWT_JWKS_FETCH_SAME_ZONE_BLOCKED"),
            (HTTPError(url, 403, "forbidden", {
                "X-Host-Authorization-Scope": "READ_ONLY_NO_MUTATION",
                "X-Host-Authorization-Reason": "DANGEROUS_SECRET_PAYLOAD",
            }, None), "GET_403_EDGE_OR_UNVERIFIED_WORKER_DENIED"),
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

    def test_active_deployment_metadata_never_claims_git_source(self):
        doc = {"success": True, "result": {"deployments": [{"versions": [
            {"version_id": "12286a19-8130-4d31-bb1d-5c7831016cdb", "percentage": 100},
        ]}]}}
        self.assertEqual(capability.active_worker_deployment(doc),
                         "SINGLE_VERSION_100_PERCENT_SOURCE_UNVERIFIED")
        doc["result"]["deployments"][0]["versions"][0]["percentage"] = 150
        self.assertEqual(capability.active_worker_deployment(doc),
                         "UNPROVEN_ACTIVE_DEPLOYMENT")
        self.assertEqual(capability.active_worker_deployment({"success": False}),
                         "UNPROVEN_DEPLOYMENTS_RESPONSE")

    def test_exact_runner_readback_uses_complete_pages_and_exposes_no_names(self):
        name = "sing-box-production-application-acceptance-4"
        required = ["self-hosted", "Linux", "X64",
                    "sing-box-production-vm", "application-acceptance-4"]
        first = {"total_count": 101, "runners": [
            {"id": i + 1, "name": f"unrelated-{i}", "status": "online",
             "busy": False, "labels": []} for i in range(100)
        ]}
        target = {"id": 101, "name": name, "status": "offline",
                  "busy": False, "labels": [{"name": x} for x in required]}
        responses = {
            "https://api.github.com/repos/iamaman11/sing-box/actions/runners?per_page=100&page=1": first,
            "https://api.github.com/repos/iamaman11/sing-box/actions/runners?per_page=100&page=2": {
                "total_count": 101, "runners": [target],
            },
        }
        def exact_get(url, token, host):
            self.assertEqual(token, "opaque-token")
            self.assertEqual(host, "api.github.com")
            return responses.get(url)
        with patch.object(capability, "observe_json", side_effect=exact_get):
            self.assertEqual(capability.registered_vm_runner(
                "iamaman11/sing-box", "opaque-token", "application-acceptance-4"),
                "RUNNER_OFFLINE")
            target["status"] = "online"
            self.assertEqual(capability.registered_vm_runner(
                "iamaman11/sing-box", "opaque-token", "application-acceptance-4"),
                "RUNNER_ONLINE_IDLE_NOT_NATIVE_PROOF")
            target["busy"] = True
            self.assertEqual(capability.registered_vm_runner(
                "iamaman11/sing-box", "opaque-token", "application-acceptance-4"),
                "RUNNER_BUSY")
            target["busy"] = False
            target["labels"] = []
            self.assertEqual(capability.registered_vm_runner(
                "iamaman11/sing-box", "opaque-token", "application-acceptance-4"),
                "RUNNER_LABEL_MISMATCH")
            target["labels"] = [{"name": x} for x in required]
            responses.pop("https://api.github.com/repos/iamaman11/sing-box/actions/runners?per_page=100&page=2")
            self.assertEqual(capability.registered_vm_runner(
                "iamaman11/sing-box", "opaque-token", "application-acceptance-4"),
                "UNPROVEN_RUNNER_INVENTORY")

    def test_runner_absence_requires_complete_inventory_not_a_queued_job(self):
        with patch.object(capability, "observe_json", return_value={
            "total_count": 0, "runners": [],
        }):
            self.assertEqual(capability.registered_vm_runner(
                "iamaman11/sing-box", "opaque-token", "application-acceptance-4"),
                "RUNNER_UNREGISTERED")
        with patch.object(capability, "observe_json", return_value={
            "total_count": 101, "runners": [],
        }):
            self.assertEqual(capability.registered_vm_runner(
                "iamaman11/sing-box", "opaque-token", "application-acceptance-4"),
                "UNPROVEN_RUNNER_INVENTORY")

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


class TestUnifiedHostDiagnosis(TestCase):
    """Physical acceptance must never be inferred from a Git or GET probe."""

    def setUp(self):
        self.git = {
            "phase": "PREPARED_GIT_ONLY",
            "owner": "VULTR_FIRST_USE_OWNER",
            "reason": "PROVIDER_AND_WORKER_PREFLIGHT_REQUIRED",
            "last_proven_step": "GIT_FIRST_USE_DIGEST_PINNED_NOT_WORKER_ATTESTED",
            "next_action": "VERIFY_WORKER_ACCESS_AND_PROVIDER_PREFLIGHT",
        }
        self.observed = {
            "scope": "READ_ONLY_PROTECTED_ENVIRONMENT",
            "machine_id": "application-acceptance-5",
            "provider_mutations": 0, "worker_mutations": 0, "github_mutations": 0,
            "vultr_machine": "LABEL_ABSENT_SINGLE_PAGE_NOT_CREATE_AUTHORITY",
            "worker_host_route_get": "GET_403_EDGE_OR_UNVERIFIED_WORKER_DENIED",
            "worker_active_deployment": "SINGLE_VERSION_100_PERCENT_SOURCE_UNVERIFIED",
            "worker_host_signing_bindings": "PRESENT_NAMES_ONLY_NOT_SIGNING_PROOF",
            "github_runner_state": "RUNNER_UNREGISTERED",
        }

    def diagnose(self):
        return summary.fuse(
            self.observed, self.git, machine_id="application-acceptance-5",
            operation_id="issue1-comment-6390000111",
            source_digest="a" * 40, release_set_sha256="b" * 64)

    def test_unproven_worker_denial_is_addressable_and_no_replay(self):
        output = self.diagnose()
        self.assertEqual(output["phase"], "WORKER_ACCESS")
        self.assertEqual(output["owner"], "CLOUDFLARE_ACCESS")
        self.assertEqual(output["reason"], "GET_403_EDGE_OR_UNVERIFIED_WORKER_DENIED")
        self.assertEqual(output["last_proven_step"], "GIT_FIRST_USE_REFERENCE_ONLY")
        self.assertFalse(output["physical_accepted"])
        self.assertFalse(output["replay_allowed"])
        self.assertEqual(output["sources"]["root_agent"],
                         "UNPROVEN_NO_SIGNED_NATIVE_OBSERVATION")
        self.assertNotIn("CF_ACCESS", json.dumps(output))

    def test_git_only_blocked_has_priority_over_unverified_get(self):
        self.git.update(phase="BLOCKED", owner="FIRST_USE_CREDENTIAL_OWNER",
                        reason="HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED")
        output = self.diagnose()
        self.assertEqual(output["phase"], "GIT_READINESS")
        self.assertEqual(output["reason"], "HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED")

    def test_absent_vm_is_not_success_or_create_admission(self):
        self.observed["worker_host_route_get"] = "GET_204_WORKER_JWT_VERIFIED_NOT_SIGNING_PROOF"
        output = self.diagnose()
        self.assertEqual(output["phase"], "BEFORE_VM_CREATE")
        self.assertEqual(output["status"], "UNPROVEN")
        self.assertFalse(output["mutation_authorized"])
        self.assertFalse(output["physical_accepted"])
        self.assertEqual(output["reason"], "HOST_VM_ABSENT_FIRST_USE_NOT_EXECUTED")

    def test_runner_online_does_not_attest_native_owner(self):
        self.observed["worker_host_route_get"] = "GET_204_WORKER_JWT_VERIFIED_NOT_SIGNING_PROOF"
        self.observed["vultr_machine"] = "EXACT_LABEL_PRESENT_NO_CREATE"
        self.observed["github_runner_state"] = "RUNNER_ONLINE_IDLE_NOT_NATIVE_PROOF"
        output = self.diagnose()
        self.assertEqual(output["phase"], "NATIVE_OBSERVATION")
        self.assertEqual(output["status"], "UNPROVEN")
        self.assertFalse(output["physical_accepted"])
        self.assertEqual(output["sources"]["signed_receipt"],
                         "UNPROVEN_GIT_PIN_IS_NOT_PHYSICAL_RECEIPT")

    def test_offline_or_unknown_runner_never_authorizes_recovery(self):
        self.observed["worker_host_route_get"] = "GET_204_WORKER_JWT_VERIFIED_NOT_SIGNING_PROOF"
        self.observed["vultr_machine"] = "EXACT_LABEL_PRESENT_NO_CREATE"
        for runner in ("RUNNER_OFFLINE", "UNPROVEN_RUNNER_API", "RUNNER_UNREGISTERED"):
            self.observed["github_runner_state"] = runner
            result = self.diagnose()
            self.assertEqual(result["phase"], "BOOTSTRAP_OR_RUNNER")
            self.assertFalse(result["replay_allowed"])
            self.assertEqual(result["sources"]["cloud_init"],
                             "UNPROVEN_NO_NATIVE_OR_PROVIDER_BOOT_JOURNAL")

    def test_provider_unknown_and_invalid_source_fails_closed(self):
        self.observed["worker_host_route_get"] = "GET_204_WORKER_JWT_VERIFIED_NOT_SIGNING_PROOF"
        self.observed["vultr_machine"] = "UNPROVEN_PAGINATED_OR_MISSING_META"
        self.assertEqual(self.diagnose()["phase"], "VULTR_INVENTORY")
        self.observed["provider_mutations"] = 1
        with self.assertRaises(ValueError):
            self.diagnose()
        self.observed["provider_mutations"] = 0
        self.observed["machine_id"] = "wrong-machine"
        with self.assertRaises(ValueError):
            self.diagnose()


if __name__ == "__main__":
    main()
