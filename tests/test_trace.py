"""Unit tests for rowid descent tracing on an accepted snapshot."""

import unittest

from app.fixtures import (
    PAGE_SIZE,
    second_valid_snapshot,
    trace_gap_snapshot,
    valid_snapshot,
)
from app.sqlite_audit import (
    TRACE_BETWEEN_KEYS,
    TRACE_FOUND,
    TRACE_LEAF_MISSING,
    TRACE_OUTSIDE_TREE,
    audit_snapshot,
    trace_rowid_path,
)


class MultiLevelHitTests(unittest.TestCase):
    """root 2 -> interior 11 -> leaves 3/4, and root right child leaf 5."""

    def setUp(self):
        self.data, self.root = valid_snapshot()
        self.assertEqual(audit_snapshot(self.data, self.root)["verdict"], "accepted")

    def test_hit_descends_through_every_interior_level(self):
        t = trace_rowid_path(self.data, self.root, 7)
        self.assertEqual(t["outcome"], TRACE_FOUND)
        self.assertEqual([s["page"] for s in t["path"]], [2, 11])
        self.assertEqual([s["child_page"] for s in t["path"]], [11, 4])
        self.assertEqual(t["leaf"]["page"], 4)
        self.assertTrue(t["leaf"]["exact_cell"])
        self.assertEqual(t["leaf"]["exact_cell_index"], 2)

    def test_half_open_bounds_come_from_adjacent_divider_keys(self):
        t = trace_rowid_path(self.data, self.root, 7)
        self.assertEqual(t["path"][0]["key_bounds"], [None, 8])
        self.assertEqual(t["path"][0]["key_bounds_label"], "(-inf, 8]")
        self.assertEqual(t["path"][0]["divider_key"], 8)
        self.assertEqual(t["path"][1]["key_bounds"], [4, None])
        self.assertEqual(t["path"][1]["key_bounds_label"], "(4, +inf]")
        self.assertIsNone(t["path"][1]["divider_key"])  # right-most pointer

    def test_boundary_rowid_follows_the_half_open_division(self):
        # divider key 4: rowid 4 belongs to the LEFT child, rowid 5 to the right.
        left = trace_rowid_path(self.data, self.root, 4)
        self.assertEqual(left["leaf"]["page"], 3)
        self.assertEqual(left["path"][-1]["choice"], "cell")
        self.assertEqual(left["path"][-1]["cell_index"], 0)
        right = trace_rowid_path(self.data, self.root, 5)
        self.assertEqual(right["leaf"]["page"], 4)
        self.assertEqual(right["path"][-1]["choice"], "right_most")
        # divider key 8 at the root splits the same way.
        self.assertEqual(trace_rowid_path(self.data, self.root, 8)["leaf"]["page"], 4)
        self.assertEqual(trace_rowid_path(self.data, self.root, 9)["leaf"]["page"], 5)

    def test_pointer_offset_is_the_raw_child_pointer_in_the_snapshot(self):
        t = trace_rowid_path(self.data, self.root, 4)  # both steps use a cell pointer
        for step in t["path"]:
            # The four bytes at the reported offset must literally name the
            # child page the descent follows.
            raw = int.from_bytes(
                self.data[step["pointer_offset"] : step["pointer_offset"] + 4],
                "big",
            )
            self.assertEqual(raw, step["child_page"])
        # Exact absolute offsets in the deterministic 1024-byte-page fixture.
        self.assertEqual(t["path"][0]["pointer_offset"], 2 * PAGE_SIZE - 5)  # 2043
        self.assertEqual(t["path"][1]["pointer_offset"], 11 * PAGE_SIZE - 5)  # 11259
        # Right-most child pointers live in the interior page header (hdr+8).
        t7 = trace_rowid_path(self.data, self.root, 7)
        self.assertEqual(t7["path"][1]["choice"], "right_most")
        self.assertEqual(t7["path"][1]["pointer_offset"], 10 * PAGE_SIZE + 8)
        right = trace_rowid_path(self.data, self.root, 9)
        self.assertEqual(right["path"][0]["pointer_offset"], PAGE_SIZE + 8)

    def test_leaf_reports_full_range_and_all_rowids(self):
        t = trace_rowid_path(self.data, self.root, 7)
        self.assertEqual(t["leaf"]["rowid_range"], [5, 8])
        self.assertEqual(t["leaf"]["rowids"], [5, 6, 7, 8])
        self.assertEqual(t["leaf"]["cell_count"], 4)
        self.assertEqual(t["tree_rowid_range"], [1, 12])

    def test_every_existing_rowid_is_found(self):
        for rowid in range(1, 13):
            with self.subTest(rowid=rowid):
                t = trace_rowid_path(self.data, self.root, rowid)
                self.assertEqual(t["outcome"], TRACE_FOUND, t["message"])
                self.assertTrue(t["leaf"]["exact_cell"])

    def test_trace_follows_raw_pointers_not_summary_ranges(self):
        # Interior divider key 5 while the left subtree ends at 4: legal
        # (4 <= 5 < 6).  A summary-range guess would put rowid 5 anywhere; the
        # raw pointer rule (rowid <= key -> left) sends it to leaf 3.
        from app.fixtures import SnapshotBuilder

        b = SnapshotBuilder(page_size=PAGE_SIZE, page_count=5)
        b.add_table_leaf(3, [(1, b"a"), (4, b"d")])
        b.add_table_leaf(4, [(6, b"f"), (8, b"h")])
        b.add_table_interior(2, [5], [3, 4])
        data = b.build()
        self.assertEqual(audit_snapshot(data, 2)["verdict"], "accepted")
        t = trace_rowid_path(data, 2, 5)
        self.assertEqual(t["outcome"], TRACE_BETWEEN_KEYS)
        self.assertEqual(t["leaf"]["page"], 3)  # reached via the raw left pointer
        self.assertEqual(t["path"][0]["divider_key"], 5)
        self.assertEqual(t["path"][0]["child_page"], 3)


class MissOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.data, self.root = trace_gap_snapshot()
        self.assertEqual(audit_snapshot(self.data, self.root)["verdict"], "accepted")

    def test_leaf_missing_inside_audited_leaf_span(self):
        t = trace_rowid_path(self.data, self.root, 3)
        self.assertEqual(t["outcome"], TRACE_LEAF_MISSING)
        self.assertEqual(t["leaf"]["page"], 3)
        self.assertEqual(t["leaf"]["rowid_range"], [1, 4])
        self.assertEqual(t["leaf"]["rowids"], [1, 2, 4])
        self.assertFalse(t["leaf"]["exact_cell"])
        self.assertIsNone(t["leaf"]["exact_cell_index"])

    def test_between_separator_boundaries_has_no_covering_leaf(self):
        t = trace_rowid_path(self.data, self.root, 5)
        self.assertEqual(t["outcome"], TRACE_BETWEEN_KEYS)
        # The descent still returns the real ordered path to the reached leaf.
        self.assertEqual([s["page"] for s in t["path"]], [2, 11])
        self.assertEqual(t["path"][-1]["choice"], "right_most")
        self.assertEqual(t["path"][-1]["key_bounds_label"], "(4, +inf]")
        self.assertEqual(t["leaf"]["page"], 4)
        self.assertEqual(t["leaf"]["rowid_range"], [6, 8])
        self.assertFalse(t["leaf"]["exact_cell"])

    def test_outcomes_are_distinguishable(self):
        outcomes = {
            trace_rowid_path(self.data, self.root, r)["outcome"]
            for r in (1, 3, 5, 13)
        }
        self.assertEqual(
            outcomes,
            {TRACE_FOUND, TRACE_LEAF_MISSING, TRACE_BETWEEN_KEYS, TRACE_OUTSIDE_TREE},
        )


class OutsideTreeTests(unittest.TestCase):
    def setUp(self):
        self.data, self.root = valid_snapshot()

    def test_below_and_above_whole_tree_range(self):
        for rowid in (0, -5, 13, 999):
            with self.subTest(rowid=rowid):
                t = trace_rowid_path(self.data, self.root, rowid)
                self.assertEqual(t["outcome"], TRACE_OUTSIDE_TREE)
                self.assertFalse(t["leaf"]["exact_cell"])
                self.assertEqual(t["tree_rowid_range"], [1, 12])

    def test_outside_still_shows_the_real_descent(self):
        t = trace_rowid_path(self.data, self.root, 13)
        self.assertEqual([s["child_page"] for s in t["path"]], [5])
        self.assertEqual(t["leaf"]["page"], 5)


class RootIsLeafTests(unittest.TestCase):
    def test_single_level_tree(self):
        data, root = second_valid_snapshot()
        t = trace_rowid_path(data, root, 100)
        self.assertEqual(t["outcome"], TRACE_FOUND)
        self.assertEqual(t["path"], [])
        self.assertEqual(t["leaf"]["page"], 2)
        self.assertEqual(t["leaf"]["rowid_range"], [100, 200])
        miss = trace_rowid_path(data, root, 7)
        self.assertEqual(miss["outcome"], TRACE_OUTSIDE_TREE)
        self.assertEqual(miss["leaf"]["page"], 2)


class RejectedSnapshotTests(unittest.TestCase):
    def test_trace_refuses_a_rejected_verdict(self):
        from app import fixtures

        data, root, *_ = fixtures.invalid_scenarios()["key_bound_conflict"]
        with self.assertRaises(ValueError):
            trace_rowid_path(data, root, 7)


if __name__ == "__main__":
    unittest.main()
