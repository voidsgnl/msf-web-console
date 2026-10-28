import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routes.db import WorkspaceRenameRequest, delete_workspace, rename_workspace


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


    def test_renaming_active_workspace_preserves_selection_and_returns_fresh_list(self):
        responses = [
            {"workspaces": [{"name": "default", "id": 1}, {"name": "lab", "id": 2}]},
            {"workspace": "lab", "workspace_id": 2},
            {"id": "9"},
            {"wrote": True},
            {"busy": True, "data": "Renamed workspace 'lab' to 'lab-new'\\n"},
            {"busy": False, "data": "msf6 > "},
            {},
            {"workspaces": [{"name": "default", "id": 1}, {"name": "lab-new", "id": 2}]},
            {"result": "success"},
            {"workspace": "lab-new", "workspace_id": 2},
            {"workspaces": [{"name": "default", "id": 1}, {"name": "lab-new", "id": 2}]},
        ]
        with patch("app.routes.db.rpc.call", side_effect=responses) as rpc_call, patch("app.routes.db.time.sleep"):
            result = rename_workspace(WorkspaceRenameRequest(old_name="lab", new_name="lab-new"))

        self.assertEqual(result["renamed_workspace"], {"old_name": "lab", "new_name": "lab-new"})
        self.assertEqual(result["current_workspace"], {"workspace": "lab-new", "workspace_id": 2})
        self.assertEqual([item["name"] for item in result["workspaces"]], ["default", "lab-new"])
        rpc_call.assert_any_call("console.write", "9", 'workspace -r "lab" "lab-new"\n')
        rpc_call.assert_any_call("db.set_workspace", "lab-new")
        rpc_call.assert_any_call("console.destroy", "9")

    def test_renaming_non_active_workspace_does_not_switch_active_workspace(self):
        responses = [
            {"workspaces": [{"name": "default"}, {"name": "lab"}]},
            {"workspace": "default", "workspace_id": 1},
            {"id": "3"},
            {"wrote": True},
            {"busy": False, "data": "Renamed workspace 'lab' to 'lab-new'\\nmsf6 > "},
            {},
            {"workspaces": [{"name": "default"}, {"name": "lab-new"}]},
            {"workspace": "default", "workspace_id": 1},
            {"workspaces": [{"name": "default"}, {"name": "lab-new"}]},
        ]
        with patch("app.routes.db.rpc.call", side_effect=responses) as rpc_call, patch("app.routes.db.time.sleep"):
            result = rename_workspace(WorkspaceRenameRequest(old_name="lab", new_name="lab-new"))

        self.assertEqual(result["current_workspace"]["workspace"], "default")
        self.assertFalse(any(call.args[:1] == ("db.set_workspace",) for call in rpc_call.call_args_list))

    def test_default_workspace_cannot_be_renamed(self):
        with patch("app.routes.db.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                rename_workspace(WorkspaceRenameRequest(old_name="default", new_name="renamed-default"))
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()

    def test_rename_rejects_command_metacharacters_before_rpc(self):
        with patch("app.routes.db.rpc.call") as rpc_call:
            with self.assertRaises(HTTPException) as raised:
                rename_workspace(WorkspaceRenameRequest(old_name="lab", new_name='new"; exit'))
        self.assertEqual(raised.exception.status_code, 400)
        rpc_call.assert_not_called()

    def test_rename_rejects_missing_source_and_duplicate_target(self):
        with patch("app.routes.db.rpc.call", return_value={"workspaces": [{"name": "default"}]}) as rpc_call:
            with self.assertRaises(HTTPException) as missing:
                rename_workspace(WorkspaceRenameRequest(old_name="missing", new_name="renamed"))
        self.assertEqual(missing.exception.status_code, 404)
        rpc_call.assert_called_once_with("db.workspaces")

        with patch("app.routes.db.rpc.call", return_value={"workspaces": [{"name": "default"}, {"name": "lab"}, {"name": "target"}]}) as rpc_call:
            with self.assertRaises(HTTPException) as duplicate:
                rename_workspace(WorkspaceRenameRequest(old_name="lab", new_name="target"))
        self.assertEqual(duplicate.exception.status_code, 409)
        rpc_call.assert_called_once_with("db.workspaces")


if __name__ == "__main__":
    unittest.main()
