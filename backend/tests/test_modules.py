import base64
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routes.modules import (
    ExecuteRequest,
    execute_module,
    module_result,
    module_running_stats,
)


class ModuleWorkflowTests(unittest.TestCase):
    def test_background_module_execution_returns_job_and_uuid(self):
        response = {"job_id": 4, "uuid": "yJWES2Y6d4MRyfFLWjqhqvon"}
        with patch("app.routes.modules.rpc.call", return_value=response) as rpc_call:
            result = execute_module(ExecuteRequest(
                type="auxiliary",
                name="scanner/test/example",
                options={"RHOSTS": "192.0.2.10"},
            ))

        self.assertEqual(result, response)
        rpc_call.assert_called_once_with(
            "module.execute", "auxiliary", "scanner/test/example", {"RHOSTS": "192.0.2.10"}
        )

    def test_payload_execution_returns_binary_safe_download_data(self):
        raw_payload = bytes([0, 1, 127, 128, 255])
        with patch("app.routes.modules.rpc.call", return_value={"payload": raw_payload}) as rpc_call:
            result = execute_module(ExecuteRequest(
                type="payload",
                name="windows/meterpreter/reverse_tcp",
                options={"Format": "exe", "LHOST": "127.0.0.1"},
            ))

        self.assertEqual(result["kind"], "payload")
        self.assertEqual(result["filename"], "reverse_tcp.exe")
        self.assertEqual(result["size"], len(raw_payload))
        self.assertEqual(base64.b64decode(result["payload_base64"]), raw_payload)
        rpc_call.assert_called_once_with(
            "module.execute", "payload", "windows/meterpreter/reverse_tcp",
            {"Format": "exe", "LHOST": "127.0.0.1"},
        )

    def test_encoder_and_nop_execution_are_rejected_before_rpc(self):
        for module_type in ("encoder", "nop"):
            with self.subTest(module_type=module_type):
                with patch("app.routes.modules.rpc.call") as rpc_call:
                    with self.assertRaises(HTTPException) as raised:
                        execute_module(ExecuteRequest(type=module_type, name="test/module"))
                self.assertEqual(raised.exception.status_code, 400)
                self.assertIn("dedicated workflow", raised.exception.detail)
                rpc_call.assert_not_called()

    def test_running_stats_proxy_returns_module_run_states(self):
        stats = {"waiting": ["runwaiting1234"], "running": ["runrunning1234"], "results": ["runresult123456"]}
        with patch("app.routes.modules.rpc.call", return_value=stats) as rpc_call:
            result = module_running_stats()
        self.assertEqual(result, stats)
        rpc_call.assert_called_once_with("module.running_stats")

    def test_module_result_validates_uuid_and_fetches_result(self):
        response = {"status": "completed", "result": {"hosts": ["192.0.2.10"]}}
        run_uuid = "yJWES2Y6d4MRyfFLWjqhqvon"
        with patch("app.routes.modules.rpc.call", return_value=response) as rpc_call:
            result = module_result(run_uuid)
        self.assertEqual(result, response)
        rpc_call.assert_called_once_with("module.results", run_uuid)

    def test_module_result_rejects_invalid_uuid_without_rpc(self):
        with patch("app.routes.modules.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                module_result("../../etc/passwd")
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()

    def test_payload_missing_binary_content_returns_upstream_error(self):
        with patch("app.routes.modules.rpc.call", return_value={"status": "success"}):
            with self.assertRaises(HTTPException) as raised:
                execute_module(ExecuteRequest(type="payload", name="test/payload"))
        self.assertEqual(raised.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()
