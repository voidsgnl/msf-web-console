import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routes.db import delete_workspace


class WorkspaceManagementTests(unittest.TestCase):
    def test_default_workspace_cannot_be_deleted(self):
        with patch("app.routes.db.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                delete_workspace("default")
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()

    def test_missing_workspace_returns_not_found_without_deleting(self):
        with patch("app.routes.db.rpc.call", return_value={"workspaces": [{"name": "default"}]}) as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                delete_workspace("missing")
        self.assertEqual(raised.exception.status_code, 404)
        rpc_call.assert_called_once_with("db.workspaces")

    def test_deleting_workspace_returns_refreshed_state(self):
        responses = [
            {"workspaces": [{"name": "default"}, {"name": "lab"}]},
            {"result": "success"},
            {"workspace": "default", "workspace_id": 1},
            {"workspaces": [{"name": "default", "id": 1}]},
        ]
        with patch("app.routes.db.rpc.call", side_effect=responses) as rpc_call:
            result = delete_workspace("lab")

        self.assertEqual(result["deleted_workspace"], "lab")
        self.assertEqual(result["current_workspace"], {"workspace": "default", "workspace_id": 1})
        self.assertEqual(result["workspaces"], [{"name": "default", "id": 1}])
        self.assertEqual(rpc_call.call_args_list[1].args, ("db.del_workspace", "lab"))

    def test_workspace_name_is_trimmed_before_lookup(self):
        with patch("app.routes.db.rpc.call", return_value={"workspaces": [{"name": "lab"}]}):
            with self.assertRaises(HTTPException) as raised:
                delete_workspace("   ")
        self.assertEqual(raised.exception.status_code, 400)

    def test_rpc_failure_is_reported_as_gateway_error(self):
        from app.msf_rpc import MsfRpcError

        with patch("app.routes.db.rpc.call", side_effect=MsfRpcError("database offline")):
            with self.assertRaises(HTTPException) as raised:
                delete_workspace("lab")
        self.assertEqual(raised.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()
