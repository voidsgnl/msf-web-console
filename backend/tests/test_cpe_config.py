import unittest

from app.cpe_config import OTHER, combine, evaluate_configurations, evaluate_node


def leaf(match):
    return match["state"]


def m(state):
    return {"state": state}


class CombineTests(unittest.TestCase):
    def test_and_requires_every_value_true(self):
        self.assertIs(combine("AND", [True, True]), True)
        self.assertIs(combine("AND", [True, False]), False)

    def test_and_with_unknown_is_unknown_unless_something_is_false(self):
        self.assertIsNone(combine("AND", [True, None]))
        self.assertIs(combine("AND", [False, None]), False)

    def test_and_with_other_product_is_unknown(self):
        self.assertIsNone(combine("AND", [True, OTHER]))

    def test_or_any_true_wins(self):
        self.assertIs(combine("OR", [None, True]), True)
        self.assertIs(combine("OR", [False, True]), True)

    def test_or_unknown_beats_false(self):
        self.assertIsNone(combine("OR", [False, None]))

    def test_or_ignores_other_product(self):
        self.assertIs(combine("OR", [OTHER, False]), False)
        self.assertIs(combine("OR", [OTHER, OTHER]), OTHER)

    def test_missing_operator_defaults_to_or_and_empty_is_unknown(self):
        self.assertIs(combine(None, [False, True]), True)
        self.assertIsNone(combine("AND", []))


class EvaluateTests(unittest.TestCase):
    def test_node_children_are_combined_with_node_operator(self):
        node = {
            "operator": "AND",
            "cpe_matches": [m(True)],
            "children": [{"operator": "OR", "cpe_matches": [m(False), m(True)]}],
        }
        self.assertIs(evaluate_node(node, leaf), True)

    def test_negate_inverts_known_results_only(self):
        self.assertIs(evaluate_node({"negate": True, "cpe_matches": [m(True)]}, leaf), False)
        self.assertIs(evaluate_node({"negate": True, "cpe_matches": [m(False)]}, leaf), True)
        self.assertIsNone(evaluate_node({"negate": True, "cpe_matches": [m(None)]}, leaf))

    def test_flat_configuration_is_one_or_node(self):
        self.assertIs(evaluate_configurations([{"cpe_matches": [m(False), m(True)]}], leaf), True)

    def test_and_configuration_needs_all_nodes(self):
        config = {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpe_matches": [m(True)]},
                {"operator": "OR", "cpe_matches": [m(None)]},
            ],
        }
        self.assertIsNone(evaluate_configurations([config], leaf))

    def test_multi_node_configuration_without_operator_is_treated_as_and(self):
        config = {
            "nodes": [
                {"operator": "OR", "cpe_matches": [m(True)]},
                {"operator": "OR", "cpe_matches": [m(None)]},
            ],
        }
        self.assertIsNone(evaluate_configurations([config], leaf))

    def test_separate_configurations_are_alternatives(self):
        configs = [
            {"nodes": [{"operator": "OR", "cpe_matches": [m(False)]}]},
            {"nodes": [{"operator": "OR", "cpe_matches": [m(True)]}]},
        ]
        self.assertIs(evaluate_configurations(configs, leaf), True)

    def test_no_configurations_is_unknown(self):
        self.assertIsNone(evaluate_configurations([], leaf))


if __name__ == "__main__":
    unittest.main()
