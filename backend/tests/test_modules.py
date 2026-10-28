import base64
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routes.modules import (
    EncodeRequest,
    ExecuteRequest,
    NopGenerateRequest,
    encode_data,
    execute_module,
    generate_nops,
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


    def test_encoder_workflow_encodes_hex_input_as_binary_safely(self):
        encoded = bytes([0, 255, 16, 128])
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[
                {"modules": ["x86/test_encoder"]},
                {"BufferRegister": {"type": "string"}, "BufferOffset": {"type": "int"}},
                {"encoded": encoded},
            ],
        ) as rpc_call:
            result = encode_data(EncodeRequest(
                name="x86/test_encoder",
                data="414243",
                data_format="hex",
                badchars="00,0a",
                iterations=2,
                module_options={"BufferRegister": "ESP", "ignored": "drop-me", "addshellcode": "/tmp/secret"},
            ))

        self.assertEqual(result["kind"], "encoder")
        self.assertEqual(result["filename"], "encoded-x86-test_encoder.bin")
        self.assertEqual(result["size"], 4)
        self.assertEqual(base64.b64decode(result["payload_base64"]), encoded)
        self.assertEqual(rpc_call.call_args_list[0].args, ("module.encoders",))
        self.assertEqual(rpc_call.call_args_list[1].args, ("module.options", "encoder", "x86/test_encoder"))
        self.assertEqual(
            rpc_call.call_args_list[2].args,
            ("module.encode", b"ABC", "x86/test_encoder", {
                "format": "raw",
                "badchars": b"\x00\x0a",
                "ecount": 2,
                "BufferRegister": "ESP",
            }),
        )

    def test_encoder_workflow_supports_base64_input(self):
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[
                {"modules": ["x86/test_encoder"]},
                {},
                {"encoded": b"result"},
            ],
        ) as rpc_call:
            result = encode_data(EncodeRequest(
                name="x86/test_encoder",
                data=base64.b64encode(b"\x00\xff").decode("ascii"),
                data_format="base64",
            ))
        self.assertEqual(base64.b64decode(result["payload_base64"]), b"result")
        self.assertEqual(rpc_call.call_args_list[2].args[1], b"\x00\xff")

    def test_encoder_rejects_unknown_module_before_encoding(self):
        with patch("app.routes.modules.rpc.call", return_value={"modules": ["x86/allowed"]}) as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                encode_data(EncodeRequest(name="x86/not-found", data="hello"))
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(rpc_call.call_count, 1)

    def test_encoder_rejects_invalid_hex_and_base64_without_rpc(self):
        for request in (
            EncodeRequest(name="x86/test_encoder", data="zz", data_format="hex"),
            EncodeRequest(name="x86/test_encoder", data="##not-base64", data_format="base64"),
            EncodeRequest(name="x86/test_encoder", data="valid", badchars="0"),
        ):
            with self.subTest(data_format=request.data_format, badchars=request.badchars):
                with patch("app.routes.modules.rpc.call") as rpc_call:
                    with self.assertRaises(HTTPException) as raised:
                        encode_data(request)
                self.assertEqual(raised.exception.status_code, 400)
                rpc_call.assert_not_called()

    def test_nop_workflow_generates_selected_module_bytes(self):
        generated = r'unsigned char buf[] = "\x90\x90\x90\x90\x90\x90\x90\x90";'
        with patch(
            "app.routes.modules.rpc.call",
            side_effect=[
                {"modules": ["x86/single_byte"]},
                {"id": 42},
                {"data": "msf6 > "},
                {"wrote": True},
                {"busy": False, "data": "Using configured NOP generator x86/single_byte\n"},
                {"busy": False, "data": ""},
                {"wrote": True},
                {"busy": False, "data": generated},
                {"busy": False, "data": ""},
                {},
            ],
        ) as rpc_call, patch("app.routes.modules.time.sleep"):
            result = generate_nops(NopGenerateRequest(
                name="x86/single_byte",
                length=8,
                badchars="00",
                save_registers=["esp", "ebp"],
            ))

        self.assertEqual(result["kind"], "nop")
        self.assertEqual(result["filename"], "nop-8-x86-single_byte.bin")
        self.assertEqual(result["size"], 8)
        self.assertEqual(base64.b64decode(result["payload_base64"]), b"\x90" * 8)
        rpc_call.assert_any_call("console.write", "42", "use nop/x86/single_byte\n")
        rpc_call.assert_any_call("console.write", "42", "generate -t c -b 00 -s esp,ebp 8\n")
        rpc_call.assert_any_call("console.destroy", "42")

    def test_nop_workflow_rejects_unknown_module_without_console(self):
        with patch("app.routes.modules.rpc.call", return_value={"modules": ["x86/single_byte"]}) as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                generate_nops(NopGenerateRequest(name="x86/not-found", length=8))
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(rpc_call.call_count, 1)

    def test_nop_workflow_rejects_invalid_register_names(self):
        with patch("app.routes.modules.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                generate_nops(NopGenerateRequest(name="x86/single_byte", length=8, save_registers=["esp; exit"]))
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()



if __name__ == "__main__":
    unittest.main()
