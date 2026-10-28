import unittest
from unittest.mock import Mock, patch

import msgpack

from app.msf_rpc import MsfRpcClient, MsfRpcError


class MsfRpcErrorDecodingTests(unittest.TestCase):
    def make_client(self) -> MsfRpcClient:
        client = MsfRpcClient()
        client.token = "test-token"
        return client

    def make_response(self, payload: dict, status_code: int = 200) -> Mock:
        response = Mock()
        response.status_code = status_code
        response.content = msgpack.packb(payload, use_bin_type=True)
        response.text = "Internal Server Error"
        return response

    @patch("app.msf_rpc.requests.post")
    def test_uses_error_string_when_error_message_is_missing(self, post):
        post.return_value = self.make_response({
            "error": True,
            "error_class": "Msf::RPC::Exception",
            "error_string": "Results not found for module instance test-run-uuid",
            "error_code": 500,
        })

        with self.assertRaises(MsfRpcError) as raised:
            self.make_client().call("module.results", "test-run-uuid")

        self.assertIn("Results not found for module instance test-run-uuid", str(raised.exception))
        self.assertIn("Msf::RPC::Exception", str(raised.exception))
        self.assertEqual(raised.exception.error_code, 500)
        self.assertIn("Results not found for module instance test-run-uuid", raised.exception.error_message)

    @patch("app.msf_rpc.requests.post")
    def test_decodes_messagepack_rpc_error_even_when_http_status_is_500(self, post):
        post.return_value = self.make_response({
            "error": True,
            "error_class": "ArgumentError",
            "error_string": "Unknown API Call: 'rpc_results'",
            "error_code": 500,
        }, status_code=500)

        with self.assertRaises(MsfRpcError) as raised:
            self.make_client().call("module.results", "test-run-uuid")

        self.assertIn("Unknown API Call: 'rpc_results'", str(raised.exception))
        self.assertEqual(raised.exception.error_code, 500)

    @patch("app.msf_rpc.requests.post")
    def test_falls_back_to_http_text_when_non_200_body_is_not_messagepack(self, post):
        response = Mock()
        response.status_code = 502
        response.content = b"upstream unavailable"
        response.text = "upstream unavailable"
        post.return_value = response

        with self.assertRaises(MsfRpcError) as raised:
            self.make_client().call("module.results", "test-run-uuid")

        self.assertIn("msfrpcd HTTP 502: upstream unavailable", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
