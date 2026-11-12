"""edges.py tests: a read in code is an edge, a read in a comment or Markdown is not, and check fails on an
undeclared read (the RED case) while a declared one passes."""
import base64
import importlib.util
import io
import marshal
import shutil
import sys
import json
import re
import os
from unittest.mock import patch
import subprocess
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import datetime
import edges as E
from plan import backstop_full, classify_paths, rule_matches

# Root's ruling on #33 round 3: computed_imports and unresolved_names are a registry, each entry with a reason and a
# review_by at most 30 days after today(). The suite pins today(); fixtures that are not about the review get REVIEW.
E.today = lambda: datetime.date(2026, 10, 29)
REVIEW = {"reason": "test fixture: reviewed with its case", "review_by": "2026-11-20"}


def reviewed_cfg(cfg: dict) -> dict:
    """The config with REVIEW on every declaration that carries neither field (the registry tests pass both)."""
    cfg = json.loads(json.dumps(cfg))
    es = cfg.get("edge_scan") or {}
    for kind in ("computed_imports", "unresolved_names"):
        if isinstance(es.get(kind), list):
            es[kind] = [{**REVIEW, **d} if isinstance(d, dict) and not ({"reason", "review_by"} & set(d)) else d
                        for d in es[kind]]
    return cfg

CFG = {
    "schema": 1,
    "workspace": {"type": "declared", "packages": {
        "a": {"dir": "services/a", "deps": []},
        "b": {"dir": "services/b", "deps": []},
    }},
    "edge_scan": {"roots": ["services"], "reader_dirs": ["scripts"], "reader_job": "root"},
    "jobs": {"root": {"packages": []}},
}


class Refusal(str):
    """A vector scan that refused: equal to "REFUSE", so every pin and comparison written against that string holds,
    and carrying the reader's ValueError text, so a vector can pin WHICH rule refused (root's item 7 of the R-c r4
    review, 2026-11-12: a refuse that accepts any ValueError also passes on a config-shape error)."""

    def __new__(cls, message: str):
        refusal = super().__new__(cls, "REFUSE")
        refusal.message = message
        return refusal


# Root's B2 of #84 and item 6 of the R-c r4 review (2026-11-12): the precision controls are a closed list. A vector
# takes `control: true` (and its truth-[] exemption) only by a one-line addition here, with its pinned `reads`; every
# label here must exist in the review vectors, so a stale entry fails too.
REVIEW_CONTROLS = (
    "A31_metadata_true", "C08_setcomp_eq_metadata_control", "D10_js_whole_statement_string_mid_file",
    "ES3_str_backslash_8_kept", "N15_sql_file_copy", "N58_json_fixture_metadata_control",
    "P13_backend_services_not_root_control", "R5R02_yaml_compose_services_key",
    "R5R03_py_database_execute_not_a_command", "R5V50_py_db_execute_precision_control",
    "R6V10_pkg_nested_scripts_object", "R6V20_pkg_precision_script_name_root",
    "R6V30_toml_key_precision", "R7T08_pkg_no_scripts_root_elsewhere", "R7T09_pkg_empty_scripts",
    "R7T10_pkg_bom_no_scripts", "R7T11_pkg_not_named_package_json", "R7T12_toml_colon_key_reads",
    "R84_B17_import_alias_name",
    # The R-c r5 vectors (root's rc-vectors-r4-1112.md items 6 and 9, and core's two 11-14 declarations), each pinned
    # in the json (`reads`), each with its declaration-only ablation.
    "RC1B_app_own_unit_declared_control", "RC1B_core_cost_centre_bare_app_declared_control",
    "RC1B_core_lead_intake_bare_app_declared_control", "RC1H_js_sibling_fallback_above_checkout_reads_nothing_control",
    "RC1H_js_sibling_fallback_control_with_reentry_files",
    "RC6D_js_fixture_name_declared_path_list_of_module_under_test_exit_control",
    "SP06_route_control", "SP07_escape_control", "T12_triple_quote_prose_control",
    "T15_jsx_text_braces_prose", "T44_ts_union_type", "T45_py_enum_member",
    "W08_invalid_escape_nonraw", "W10_newline_escape_precision_control",
    # Root's round-6 inputs (github-86-r5fix-1112.md, 2026-11-12): the two with truth [], root's own `control` and the
    # nested-package control judged on unit b, both reading [] on main, the parent and the head.
    "N00_nested_control_unit_b", "U_K_no_syspath_negative",
)

# Root's ruling change on #84 (dotgithub-84-1112.md:27, 2026-11-12): the dated known fail-opens, each pinned by a vector
# carrying `known_fail_open` {gap, until, today, record}. Its reading must EQUAL `today`, so the day a rule closes the gap
# the pin goes red and that commit removes it (the case is then judged as the read it is); on or after `until` a case
# still pinned fails. Root's B1 of dotgithub-86 (2026-11-12): the closed set is the LABELS, as REVIEW_CONTROLS is, each
# with its gap, asserted both ways (a pinned vector outside the map, an entry without its vector and an entry whose
# vector names another gap all fail), and judge() honours a pin only for a label here, so a four-key block on a failing
# read is not a way to pass. A commit that closes a gap removes its entries here and its pins in the json together.
KNOWN_FAIL_OPEN = {
    "KFO_D1_K3a_subscript_store": "D1", "KFO_D1_K3b_append_mutator": "D1", "KFO_D1_K3c_class_attr_via_self": "D1",
    "KFO_D1_K3d_setattr": "D1", "KFO_D1_K3e_nested_attr": "D1", "KFO_D1_K3f_environ_store": "D1",
    "KFO_D1_K3l_dict_update": "D1",
    "KFO_D2_K2q_from_import_out_of_pkg": "D2", "KFO_D2_K2q_from_import_out_of_pkg_m": "D2",
    "KFO_D2_K2r_star_out_of_pkg": "D2",
    "KFO_D3_K1a_chain_two_links": "D3", "KFO_D3_K1f_toplevel_link_to_shared": "D3",
    "KFO_D3_K1g_toplevel_link_unowned": "D3",
    "KFO_D4_K1jL_single_link_literal_twin": "D4",
    "KFO_C01_js_name_indirection": "C01", "KFO_C02_js_two_leading_subst": "C02", "KFO_C03_js_pkg_holding_top_subst": "C03",
    "KFO_C04_js_prefix_of_pkg_name": "C04",
    "KFO_N3_A6_unowned_free_top_landing_external": "N3",
    # Root's ROWs of dotgithub-86 slice 2 (rule (b) reads only the key; reassign and addsitedir record no entry): an
    # undeclared entry with no literal tail, and every other rule-(b) case below truth (root's 13:01 condition (b)).
    "KFO_S2R_B1_name_undecl": "S2R", "KFO_S2R_B4_empty_undecl": "S2R", "KFO_S2R_C_extend_name_undecl": "S2R",
    "KFO_S2R_F_symlink_undecl": "S2R", "KFO_S2R_D_case_undecl": "S2R", "KFO_S2R_D_abs_undecl": "S2R",
    "KFO_S2R_D_expanduser_undecl": "S2R",
    # Root's round-5 STACK CHANGES of dotgithub-86 (2774a421f815, 14:27 2026-11-12): `sys .path` spacing with a bare
    # name (N39), and the bare tail forms outside the listed ones (D04c dirname, D04d Path(..).parent, D04e a slice,
    # D04f str.replace): [] on main, dcf6545 and 2774a421, each the only sys.path site of its file, so B2 leaves it.
    # R6-2 (measured on ed22d7d8782b, 2026-11-12): N39 and the slice-2 C_reassign / C_addsitedir pins left this map, and
    # with them root's B8 eleven (U_S_*) and five of B7's nine (U_E_N18/N19/N20/N54, U_E_exec_same_file): each now
    # refuses (N39 by rule (b) once the widened listing parses it, the rest at the single refuse point) and is a refuse
    # vector pinned to its rule.
    "KFO_S5F_D04c_undeclared_dirname_bare": "S5F", "KFO_S5F_D04d_undeclared_Path_parent_bare": "S5F", "KFO_S5F_D04e_undeclared_slice_bare": "S5F",
    "KFO_S5F_D04f_undeclared_replace_bare": "S5F",
    # Root's round-6 CHANGES of dotgithub-86 (lanes/root/reviews/github-86-r5fix-1112.md, CHANGES at ff414447542b,
    # 16:13 2026-11-12) and its R6 ruling: root's 111 inputs enter the vectors verbatim (R6-1); the 49 below truth on
    # main, the parent and the head are pinned at the head's reading, each under the record's blocker: B5 (:4387
    # startswith misses the link as the landing, as an intermediate component, link then `..`; a zip on the path), B6
    # (:4380 a value normalising to `../` returns without refuse or credit), B7 (:4461-4485 the evaluated route narrows
    # by names: nine rows), B8 (ruling B2 not general: the eleven unseen forms beside one resolvable entry), K04 (a
    # PYTHONPATH in a workflow env) and B2 (the conftest landing credited only to the owning package). R6-2 to R6-5
    # remove each pin as its slice reads or refuses the input.
    "A01_eval_parents3_reenter_own_name": "R6B6", "U_A_dirname4_beside_linked_sibling": "R6B6",
    "U_A_dirname4_reenter_own_name": "R6B6",
    "K04_workflow_pythonpath_env": "R6K04",
    "N13e_conftest_evaluated_unit_rsub": "R6B2",
    "P04_eval_zip_on_path": "R6B5", "P04b_eval_zip_on_path_parents2": "R6B5", "U_P01_landing_is_tracked_symlink": "R6B5",
    "U_P02_symlink_intermediate": "R6B5", "U_P03_symlink_then_dotdot": "R6B5", "U_P04_zip_on_path": "R6B5",
    "U_E_C4_semicolon": "R6B7", "U_E_C4b_if_oneliner": "R6B7", "U_E_C4c_try_oneliner": "R6B7",
    "U_E_C4e_unparseable_sibling": "R6B7",
}

# Root's R6 ruling (1) of dotgithub-86 (16:13 2026-11-12; design line 7 accepted 16:44): the no-regression gate runs
# MAIN's reader beside the head's on every review vector (test_r6_no_regression_against_main_reader). MAIN_EDGES_BLOB is
# the git blob of edges.py on origin/main the gate was derived against (0ff30f1ad9ce and 75e84a53527e carry it,
# 2026-11-12), read with `git cat-file` from the clone (planner-tests checks out with fetch-depth 0 for it). The gate
# re-reads origin/main: while the head's edges.py differs from main's, main's blob must still BE this one, so a PR under
# which main's reader moved is an admission change that re-derives the gate and re-pins here; once the head and main
# are the same reader (main itself), the pin must name a former main edges.py, so it cannot point at nothing.
MAIN_EDGES_BLOB = "5449e5f68aa251ef8a66db44316cad70af8e21e4"
MAIN_EDGES_PATH = "actions/change-impact-plan/edges.py"
# Root's B1 and S5 of dotgithub-86 (ruling 09:03, 2026-11-12): ONE date. Every pin's `until` must EQUAL it, so no pin
# carries its own later date; the expiry is judged against the real UTC date (test_review_vector_closed_lists_hold).
KNOWN_FAIL_OPEN_UNTIL = "2026-11-28"

# Root's R4 of R6-1 (17:51 2026-11-12): a suite red by design hides a new red, so the designed-red set is closed and
# compared BY NAME. Each test below collects the labels whose judgement failed and asserts that set EQUALS its entry
# here: a 47th label (a new red), a label gone green (a slice read it: move it out here, in the same commit) and a
# label no vector carries each fail by name, and the suite is GREEN exactly when the set matches. The sets are the
# R6-1 head's (bd87cffc7f7f: local 742 s run and hosted run 43217057338 read the same 46).
DESIGNED_RED = {
    # test_review_vectors_read_their_truth_or_refuse: the 28 of ff414447 (round-5 rule pins) and root's nine of the
    # 16:13 ruling (main refuses, the head reads [] below truth). Re-judged on the R6-2 scanner (ed22d7d8782b, 2026-11-12):
    # all 37 stay red and none moves; the 28 do not wait on the refuse point after all, each fails on its own rule (a
    # reach list, code the scan excludes, a name that names no tracked file), none on a path-mutation capability.
    "review": frozenset({
        "C01_case_variant_empty_rest", "C03_linked_sibling_empty_rest", "C04_prefix_name_empty_rest",
        "C05_suffix_name_empty_rest", "C07_deeper_beside_linked_parent", "G03_generated_start_excluded_landing_dropped",
        "N13b_D13b_unit_rsub", "N13c_conftest_literal_unit_rsub", "P05_generated_start_symlink",
        "RC1F_py_two_subdirs_declared_whole_prefix", "RC1F_refuse_reach_strict_subset_of_prefix",
        "RC1F_unowned_caller_reach_strict_subset_reads_less_today",
        "RC1G_js_in_checkout_fallback_declared_external_refuses", "RC1G_js_in_checkout_fallback_declared_fixture_refuses",
        "RC1G_js_in_checkout_fallback_declared_package_refuses", "RC1G_js_sibling_load_declared_fixture_refuses",
        "RC1G_js_sibling_load_declared_package_refuses", "RC1I_f1_str_concat_declared",
        "RC1K_js_env_only_load_declared_fixture_refuses", "RC1S_backslash_parent_step_declared_refuses",
        "RC1S_py_sys_path_os_sep_join_literals_b1", "RC1X_py_one_expression_sys_path_and_run_path_one_entry_refuses",
        "RC1X_py_param_root_and_module_root_one_entry_refuses",
        "RC4B_js_whole_checkout_template_excluded_top_dir_declared_none",
        "RC5B_py_literal_route_to_excluded_code_declared_reach_list", "RC5E_py_declared_reach_list_direct_edge_only",
        "RC5F_py_scripts_caller_declared_reach_list_judged_on_readers", "RC5G_py_declared_reach_list_full_two_routes",
        "RC5J_py_two_route_hook_and_cd_route_full_reach_refuses", "RC5J_py_two_route_hook_and_cd_route_partial_reach_refuses",
        "RC5J_py_two_route_hook_own_line_cd_full_reach", "RC6B_extensionless_loader_target_declared_sources",
        "RC6B_js_loader_literal_untracked_build_output_declared_sources", "RC6B_node_addon_declared_native_sources",
        "RC6G_py_fixture_route_declared_reach_own_unit_refuses", "RC6H_refuse_reach_names_the_namer_itself",
        "RC6I_refuse_reach_names_only_the_callers_own_unit",
    }),
    # test_r6_no_regression_against_main_reader: exactly root's nine (main REFUSE, head reads [] below truth).
    "gate": frozenset({
        "C01_case_variant_empty_rest", "C03_linked_sibling_empty_rest", "C04_prefix_name_empty_rest",
        "C05_suffix_name_empty_rest", "C07_deeper_beside_linked_parent", "G03_generated_start_excluded_landing_dropped",
        "N13b_D13b_unit_rsub", "N13c_conftest_literal_unit_rsub", "P05_generated_start_symlink",
    }),
}

# Root's S1 of dotgithub-86 (2026-11-12): the `"r5": true` opt-in is closed. Exactly R5_VECTOR_COUNT vectors carry it
# (equality, so an addition is a deliberate edit here), and they are exactly the `RC` labels outside the five #84
# vectors below that predate round 5, so dropping the flag from one vector (or swapping a drop for an addition) cannot
# take it out of the ablation and expected_rule checks.
R5_VECTOR_COUNT = 168  # slice 2 FIX: + the 25 RC1T vectors (root's A/B/P probe cases); slice 3 FIX: + the two RC1A climb twins
R5_PREFIX = "RC"
RC_LABELS_BEFORE_R5 = ("RC1I_f1_fstring", "RC1I_f1_os_path_join", "RC1I_f1_str_concat", "RC1I_f1_str_path_div",
                       "RC4G_f2_unreached_scripts_template_starts_no_unit")

# Root's S2 of dotgithub-86 (2026-11-12): the reader's catch-all refusal, apply_entry's `kind == "unknown"` raise in
# edges.py (a sys.path or pytest pythonpath entry that cannot be evaluated). It fires with or without a round-5 rule, so
# an `expected_rule` (or `ablation_expected_rule`) it also contains cannot tell the new rule from it: assert_rule refuses
# such a fragment, and test_review_vector_closed_lists_hold asserts the template is still edges.py's, so this check
# cannot go vacuous when the message changes.
CATCH_ALL_REFUSAL = "unresolved (a {what} that may leave its package, `{value}`, cannot be evaluated) in {where}"
CATCH_ALL_WHATS = ("sys.path entry", "pytest pythonpath entry")

# Root's N of dotgithub-86 (09:39, 2026-11-12): the pinned-rules floor is equality on the count, not > 0. Exactly
# R5_SYS_PATH_RULE_PINS pins (22 expected_rule, 3 ablation_expected_rule: the 25 S2 re-marked) name the r5 sys.path
# rule's fragment, which test_review_vector_closed_lists_hold also pins against the text edges.py raises.
R5_SYS_PATH_RULE = "an undeclared sys.path entry"
R5_SYS_PATH_RULE_PINS = 25
# Slice 2 of the rule commits (RC1B, root's dotgithub-86 review, 2026-11-12): the rules the RC1B vectors name, closed the
# same way. Each fragment maps to (the number of pins naming it, by equality; the text of ITS raise site in edges.py).
# The raise site, not the fragment: `stale computed_imports entry` is also assess's check-mode text, so a fragment
# pin would hold on an edges.py without the scan() rule.
RC1B_RULE_PINS = {
    "a sys.path entry is declared with a reach list": (2, 'but a sys.path entry is declared with "'),
    "trailing components": (6, 'f"trailing components are not `{tail}`'),
    "is not a tracked directory": (2, 'f"not a tracked directory) in {where}"'),
    "stale computed_imports entry": (3, 'raise ValueError(f"stale computed_imports entry: '),
    # Root's B1/B2 of slice 2 (2026-11-12): a declared entry whose path has no literal tail of a listed form refuses
    # (the RC1T vectors), and rule (b), apply_entry's undeclared-tail refusal, pinned by its own raise site.
    # 16 + R86S23_declared_prefixed_parent_step_refuses_no_tail (the s2+s3 stack: no tail after the parent-step route).
    "has no tail the scan reads": (17, 'has no tail the scan reads: its last path "'),
    # R6-2 (2026-11-12): + KFO_S5F_N39_sys_space_bare_name, which the widened Python listing now parses and rule (b) refuses.
    "may land in": (6, 'f"unresolved (an undeclared sys.path entry `{key}` may land in "'),
}
# Slice 3 (RC1A, root's R-c r2 B1, r3 item 3, r4 items 5 and 11; dotgithub-86, 2026-11-12): the rules an undeclared
# parent-step sys.path literal refuses by, closed the same way. `code the scan excludes` is also the closure's text (the
# RC4 and RC5 vectors name it), so its count is every pin naming it and its site is apply_entry's RC1A raise.
RC1A_RULE_PINS = {
    "lands in no tracked directory": (4, 'lands in no tracked directory: from each one "'),
    "a symlink component": (3, 'a symlink component, "'),
    "code the scan excludes": (13, 'lands in {landing}, code the scan "'),
}
# Root's slice 3 CHANGES (dotgithub-86, 12:02 2026-11-12): B2 credits a climb above the checkout that re-enters it by its
# own name, so the depth-0/1 re-entries (RC1A_depth0/depth1_cwd_reentry_by_own_name_reads, renamed by root's 12:43
# ruling) read their truth, and their twins whose climb names no own name (RC1A_refuse_depth0/depth1_cwd_climb_names_
# no_own_name) refuse, so `lands in no tracked directory` stays at 4 pins and R5_VECTOR_COUNT gains the two twins; B4
# judges a package-free landing by the parsed names, so the R86S3_C4/C4b/C4c siblings refuse as C4ctrl does (`a
# package-free landing` 1 -> 4). B4's new refusal (a package file that does not parse) is pinned here the same way.
# Root's round-5 STACK CHANGES of dotgithub-86 (2774a421f815, 14:27 2026-11-12), B1 (a declared parent-step literal's
# reach validated and credited), B2 (a file reads only when every sys.path site resolves), B4 (a climb beside the
# checkout refuses), B5 (a symlink or a sourceless .pyc inside a landing): each fragment -> (pins naming it, by
# equality; its raise site in edges.py; a named control vector that must carry it), walked with the floor below.
R5F_RULE_PINS = {
    "but a parent-step literal is declared with a reach list": (1, '"but a parent-step literal is declared with a reach list: the tracked directories "', "R86S5F_N10_declared_parent_literal_with_keyword_reach"),
    "neither one of its landings nor a tracked directory": (1, "which is neither one of its landings nor a tracked directory) in ", "R86S5F_N01d_declared_literal_reach_not_a_landing_tracked_cwd"),
    # R6-2 (2026-11-12): 5 -> 4, R86S5F_N52's `site.addsitedir` now refuses first at the single refuse point (R6 rule).
    # W1b (2026-11-12): 4 -> 5, the carve-out twin R6_carveout_residual_beside_entry_refuses pins it.
    "a file reads only when every one of its sys.path sites resolves": (5, 'its sys.path sites resolves) in {path}"', "R86S5F_N03_declared_literal_beside_undeclared_name"),
    "where it may re-enter the checkout by a path the scan cannot see": (3, '"checkout, where it may re-enter the checkout by a path the scan cannot see; a climb "', "R86S5F_N15_beside_dir_then_dotdot_reenters"),
    "a sourceless .pyc": (2, 'else "a sourceless .pyc"', "R86S5F_N24_sourceless_pyc_in_landing"),
    "a symlink inside the landing": (2, '"a symlink inside the landing" if tracked.get(held)', "R86S5F_N28_symlink_inside_owned_landing"),
    "the repository root or above it": (12, "the repository root or above it", "R86S3_C12_dotdot_only_nested"),
}
RC1A_FIX_RULE_PINS = {
}
# R6-2 of dotgithub-86 (root's R6 acceptance 16:44 2026-11-12, decisions (i)-(iii); cli's scanner draft ed22d7d8782b):
# python_file_facts' single refuse point, the first path-mutation capability occurrence no read rule consumes. Every
# vector it refuses pins this clause (a twin may pin the named occurrence before it), closed by equality on the count as
# the rules above are. The template is split over two f-strings in edges.py, so both halves are pinned as raise sites.
R6_CAPABILITY_RULE = "is consumed by no read rule; a file reads only when every one is"
R6_CAPABILITY_RULE_PINS = 98  # W1b (2026-11-12): + the 35 R6_ refuse twins, each pinning its named occurrence and the clause
R6_CAPABILITY_SITES = ('raise ValueError(f"unresolved (the path-mutation capability `{segment}` on line {lineno} of {path} '
                       'is consumed by "', 'f"no read rule; a file reads only when every one is) in {path}")')


def catch_all_fragments():
    """The literal text of every rendering of CATCH_ALL_REFUSAL: the parts between its `{value}` and `{where}`."""
    return [part for what in CATCH_ALL_WHATS
            for part in re.split(r"\{value\}|\{where\}", CATCH_ALL_REFUSAL.replace("{what}", what)) if part]


def catch_all_pattern():
    """CATCH_ALL_REFUSAL as a regex matching every message it renders, whatever its `value` and `where`: a fragment that
    straddles a placeholder (`cannot be evaluated) in services`) is in no literal part, yet is found in a catch-all."""
    what = "|".join(re.escape(w) for w in CATCH_ALL_WHATS)
    return "".join(f"(?:{what})" if part == "{what}" else ".*" if part in ("{value}", "{where}") else re.escape(part)
                   for part in re.split(r"(\{what\}|\{value\}|\{where\})", CATCH_ALL_REFUSAL) if part)


class EdgesTest(unittest.TestCase):
    def setUp(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        isolated = patch.dict(os.environ, environment, clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)
        self._td = tempfile.TemporaryDirectory()
        self.repo = Path(self._td.name)
        for d in ("services/a", "services/b", "scripts", ".github"):
            (self.repo / d).mkdir(parents=True)
        (self.repo / "services/a/app.py").write_text("x = 1\n# reads services/b only in a comment\n")
        (self.repo / "services/a/README.md").write_text("see services/b\n")
        (self.repo / "services/b/app.py").write_text("y = 2\n")
        (self.repo / "scripts/run.sh").write_text("cd services/b\n")
        self.write_cfg(CFG)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)

    def tearDown(self):
        self._td.cleanup()

    def write_cfg(self, cfg):
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))

    def run_check(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo)])
        return rc, buf.getvalue()

    def test_comments_and_markdown_are_not_reads(self):
        deps, readers = E.scan(self.repo, CFG)
        self.assertEqual(deps, {"a": set(), "b": set()})
        self.assertEqual(readers, {"scripts": {"b"}})

    def test_undeclared_reader_fails_then_declared_passes(self):
        rc, out = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("scripts/ reads b", out)
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)

    def test_planted_code_read_is_red(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        self.write_cfg(cfg)
        (self.repo / "services/a/app.py").write_text('DATA = "services/b/data.json"\n')
        rc, out = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("undeclared read: a reads b", out)
        cfg["workspace"]["packages"]["a"]["deps"] = ["b"]
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)

    def test_nearby_github_host_text_cannot_hide_a_local_reader(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        for host in ("github.com", "github.com.invalid", "evilgithub.com"):
            with self.subTest(host=host):
                (self.repo / "services/a/app.py").write_text(f'url = "{host}"; DATA = "services/b/app.py"\n')
                self.write_cfg(cfg)
                self.assertEqual(self.run_check()[0], 1, "nearby host text must not suppress the local read")
                cfg["workspace"]["packages"]["a"]["deps"] = ["b"]
                self.write_cfg(cfg)
                self.assertEqual(self.run_check()[0], 0)
                cfg["workspace"]["packages"]["a"]["deps"] = []


    def test_unmapped_reader_is_unknown_not_an_empty_success(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"]["packages"] = ["b"]
        self.write_cfg(cfg)
        (self.repo / "other-tests").mkdir()
        (self.repo / "other-tests/read.py").write_text('input = "services/a/app.py"\n')
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        rc, output = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("unmapped source readers", output)

    def always_cfg(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"] = "always"
        cfg["edge_scan"]["always_reader_dirs"] = ["scripts"]
        return cfg

    def test_always_reader_dirs_are_left_out_of_the_scan(self):
        """A directory whose files run only in `always` jobs cannot change a selection (no plan skips an `always` job),
        so a construct the scanner cannot read there no longer refuses, which planned every change FULL. The same
        construct anywhere else still refuses under the same config, and an undeclared directory still refuses."""
        refusing = 'p = os.path.join(ROOT, "services", "..", "b")\n'
        (self.repo / "scripts/gate.py").write_text(refusing)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        undeclared = json.loads(json.dumps(CFG))
        undeclared["jobs"]["root"] = "always"
        with self.assertRaises(ValueError):
            E.scan(self.repo, undeclared)  # control: not declared always-only, the parent step refuses
        cfg = self.always_cfg()
        self.assertEqual(E.scan(self.repo, cfg), ({"a": set(), "b": set()}, {"scripts": set()}))
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)
        # The same through an immutable revision, as action.yml runs `check --revision`.
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "commit", "-qm", "always", "--no-gpg-sign"], check=True)
        head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.assertEqual(E.scan(self.repo, cfg, revision=head)[1], {"scripts": set()})
        # FAIL-CLOSED ELSEWHERE: the same construct in a package still refuses under the same config.
        (self.repo / "services/a/gate.py").write_text(refusing)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        with self.assertRaises(ValueError):
            E.scan(self.repo, cfg)

    def test_always_reader_dirs_refuse_every_declaration_that_could_hide_a_selecting_read(self):
        cases = {
            "the reader job selects (not always)": lambda c: c["jobs"].update(root={"packages": []}),
            "no reader job": lambda c: c["edge_scan"].pop("reader_job"),
            "a reader job that does not exist": lambda c: c["edge_scan"].update(reader_job="missing"),
            "not a declared reader directory": lambda c: c["edge_scan"].update(reader_dirs=[]),
            "a nested path": lambda c: c["edge_scan"].update(always_reader_dirs=["scripts/sub"], reader_dirs=["scripts/sub"]),
            "a parent step": lambda c: c["edge_scan"].update(always_reader_dirs=[".."], reader_dirs=[".."]),
            "a glob": lambda c: c["edge_scan"].update(always_reader_dirs=["scr*"], reader_dirs=["scr*"]),
            "a scan root": lambda c: c["edge_scan"].update(always_reader_dirs=["services"], reader_dirs=["services"]),
            # A root that holds no package yet: only the root check catches it (files under it are unmapped readers).
            "a scan root holding no package": lambda c: c["edge_scan"].update(
                roots=["services", "tools"], always_reader_dirs=["tools"], reader_dirs=["tools"]),
            "a directory holding a workspace package": lambda c: c["workspace"]["packages"].update(
                tool={"dir": "scripts/tool", "deps": []}),
            "an empty list": lambda c: c["edge_scan"].update(always_reader_dirs=[]),
            "not a list": lambda c: c["edge_scan"].update(always_reader_dirs="scripts"),
            "a repeated directory": lambda c: c["edge_scan"].update(always_reader_dirs=["scripts", "scripts"]),
        }
        self.assertEqual(E.scan(self.repo, self.always_cfg())[1], {"scripts": set()}, "control: the safe declaration scans")
        for why, mutate in cases.items():
            with self.subTest(why):
                cfg = self.always_cfg()
                mutate(cfg)
                with self.assertRaises(ValueError):
                    E.scan(self.repo, cfg)
        # 1.5.0: a package that imports a file in the directory runs it in every job that runs the package, so the
        # directory is not always-only, whatever the config says (cli, 2026-10-27: vagaris server imports scripts/).
        (self.repo / "services/a/uses.mjs").write_text('import { h } from "../../scripts/helper.mjs";\n')
        (self.repo / "scripts/helper.mjs").write_text("export const h = 1;\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        with self.assertRaisesRegex(ValueError, "always_reader_dirs"):
            E.scan(self.repo, self.always_cfg())

    def test_a_change_inside_an_always_reader_dir_still_plans_full(self):
        """Leaving the directory out of the scan scopes its READS only; its own files stay unmapped."""
        import plan
        cfg = self.always_cfg()
        pkgs = E.workspace_graph(self.repo, cfg)
        evidence = plan.classify_paths(["scripts/gate.py"], cfg, pkgs)["evidence"]
        self.assertEqual(evidence["unmapped"], ["scripts/gate.py"])

    def test_external_readers_require_an_actual_mapped_obligation(self):
        cfg = json.loads(json.dumps(CFG))
        cfg["jobs"]["root"] = {"packages": ["b"]}
        cfg["edge_scan"].pop("reader_job")
        self.write_cfg(cfg)
        rc, output = self.run_check()
        self.assertEqual(rc, 1)
        self.assertIn("no valid declared reader job", output)
        cfg["edge_scan"]["reader_job"] = "missing"
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 1)
        cfg["edge_scan"]["reader_job"] = "root"
        cfg["jobs"]["root"] = "full_only"
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 1)
        for rule in ("always", {"packages": ["b"]}):
            cfg["jobs"]["root"] = rule
            self.write_cfg(cfg)
            self.assertEqual(self.run_check()[0], 0)

    def test_component_joins_and_relative_paths_are_reads(self):
        (self.repo / "services/c").mkdir(parents=True)
        (self.repo / "services/c/test").mkdir()
        shapes = {
            "pathlib join": ('P = ROOT / "services" / "b" / "app.py"\n', "py"),
            "os.path.join": ('P = os.path.join(ROOT, "services", "b")\n', "py"),
            "relative URL": ('const p = new URL("../../b/app.py", import.meta.url)\n', "js"),
            "go relative read": ('right, e := os.ReadFile("../../b/app.py")\n', "go"),
        }
        cfg = json.loads(json.dumps(CFG))
        cfg["workspace"]["packages"]["c"] = {"dir": "services/c", "deps": []}
        for name, (line, ext) in shapes.items():
            with self.subTest(name):
                for old in (self.repo / "services/c/test").glob("x.*"):
                    old.unlink()
                (self.repo / f"services/c/test/x.{ext}").write_text(line)
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                deps, _ = E.scan(self.repo, cfg)
                self.assertEqual(deps["c"], {"b"}, name)
        for old in (self.repo / "services/c/test").glob("x.*"):
            old.unlink()
        (self.repo / "services/c/test/x.py").write_text('local = "../fixtures/a.json"\n')
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        deps, _ = E.scan(self.repo, cfg)
        self.assertEqual(deps["c"], set(), "a relative path inside its own package is not a cross-package read")


    def pnpm_fixture(self):
        packages = {"server": "server", "cli": "cli", "ui": "ui",
                    "sdk": "packages/plugins/sdk", "plugin": "packages/plugins/plugin"}
        (self.repo / "pnpm-workspace.yaml").write_text('packages:\n  - "server"\n  - "cli"\n  - "ui"\n  - "packages/plugins/*"\n')
        for name, directory in packages.items():
            path = self.repo / directory
            path.mkdir(parents=True, exist_ok=True)
            (path / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
        (self.repo / "server/test.ts").write_text('import "../cli/a.js";\n')
        (self.repo / "cli/test.ts").write_text('import "../packages/plugins/sdk/index.js";\n')
        (self.repo / "ui/test.ts").write_text('import "../server/index.js";\n')
        nested = self.repo / "packages/plugins/plugin/src"
        nested.mkdir()
        (nested / "odd:name\nfile.ts").write_text('import "../../sdk/index.js";\n')
        cfg = {"schema": 1, "workspace": {"type": "pnpm"},
               "edge_scan": {"roots": ["server", "cli", "ui", "packages"]}, "jobs": {}}
        self.write_cfg(cfg)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        return cfg

    def test_pnpm_nested_packages_and_cross_surface_test_readers_are_accounted(self):
        cfg = self.pnpm_fixture()
        deps, _ = E.scan(self.repo, cfg)
        expected = {"server": {"cli"}, "cli": {"sdk"}, "ui": {"server"}, "plugin": {"sdk"}, "sdk": set()}
        self.assertEqual(deps, expected)
        self.assertEqual(self.run_check()[0], 1)
        cfg["workspace"]["extra_deps"] = {name: sorted(values) for name, values in expected.items() if values}
        self.write_cfg(cfg)
        self.assertEqual(self.run_check()[0], 0)
        # Planner and checker share the same graph, including test-only cross-package reads.
        graph = E.workspace_graph(self.repo, cfg)
        import plan
        self.assertEqual(plan.reverse_closure(graph, {"sdk"}), {"sdk", "plugin", "cli", "server", "ui"})

    def test_complete_nested_component_joins_preserve_reader_ownership(self):
        cfg = self.pnpm_fixture()
        cfg["edge_scan"].update(reader_dirs=["scripts"], reader_job="root")
        cfg["workspace"]["extra_deps"] = {"server": ["cli"], "cli": ["sdk"], "ui": ["server"], "plugin": ["sdk"]}
        cfg["jobs"]["root"] = {"packages": []}
        for expression in (
            'path.join(root, "packages", "plugins", "sdk", "index.js")',
            'ROOT / "packages" / "plugins" / "sdk" / "index.js"',
            'os.path.join(ROOT, "packages", "plugins/sdk", "index.js")',
        ):
            with self.subTest(expression=expression):
                (self.repo / "scripts/read.js").write_text("read(" + expression + ");\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                self.write_cfg(cfg)
                self.assertEqual(E.scan(self.repo, cfg)[1]["scripts"], {"sdk"})
                self.assertEqual(self.run_check()[0], 1, "undeclared SDK reader must be red")
                cfg["jobs"]["root"]["packages"] = ["sdk"]
                self.write_cfg(cfg)
                self.assertEqual(self.run_check()[0], 0)
                cfg["jobs"]["root"]["packages"] = []

    def test_computed_or_unowned_component_joins_read_every_package_beneath_their_literal_prefix(self):
        """A computed component cannot be resolved statically, so the join reads EVERY package under its literal
        prefix: an over-approximation, which only runs more. A literal path no package owns reads the packages beneath
        it; with none beneath it, it is unowned content, whose change is unmapped and plans FULL, so it needs no edge.
        A `..` component still refuses."""
        cfg = self.pnpm_fixture()
        cfg["edge_scan"].update(reader_dirs=["scripts"], reader_job="root")
        cases = {
            'path.join(root, "packages", "plugins")': {"sdk", "plugin"},
            'path.join(root, "packages", "plugins", "missing", "index.js")': set(),
            'path.join(root, "packages", pluginName, "index.js")': {"sdk", "plugin"},
            'path.join(root, "packages", "plugins", "sdk", selectedFile)': {"sdk"},
            'ROOT / "packages" / pluginName': {"sdk", "plugin"},
            'ROOT / "server" / name': {"server"},
            'os.path.join(ROOT, "server")': {"server"},
        }
        for expression, expected in cases.items():
            with self.subTest(expression=expression):
                (self.repo / "scripts/read.js").write_text("read(" + expression + ");\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                self.assertEqual(E.scan(self.repo, cfg)[1]["scripts"], expected)
        for expression in ('ROOT / "packages" / ".." / "server"', 'path.join(root, "packages", "../server")'):
            with self.subTest(expression=expression):
                (self.repo / "scripts/read.js").write_text("read(" + expression + ");\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                with self.assertRaisesRegex(ValueError, "workspace-root reader expression"):
                    E.scan(self.repo, cfg)

    def test_a_root_literal_is_metadata_only_with_positive_evidence(self):
        """Root's principle (2026-10-26): METADATA needs POSITIVE evidence (an object key or value, a subscript key, a
        comparison, a .sql file, or a literal list that is assigned, an object value or compared); EVERYTHING ELSE
        REFUSES, which plans FULL. Controls: the same literal in a path call or after a pathlib `/` IS a read, and a
        walker's root list reads every package under each root."""
        cfg = json.loads(json.dumps(CFG))
        cfg["edge_scan"]["roots"] = ["services", "apps"]
        cfg["workspace"]["packages"]["web"] = {"dir": "apps/web", "deps": []}
        (self.repo / "apps/web").mkdir(parents=True)
        (self.repo / "apps/web/page.tsx").write_text("export default 1\n")

        def scan(src, ext):
            for old in (self.repo / "services/a").glob("probe.*"):
                old.unlink()
            (self.repo / f"services/a/probe.{ext}").write_text(src + "\n")
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            return E.scan(self.repo, cfg)[0]["a"]

        # Round 4 (root, 2026-10-26): "reads nothing" only for ratified positive-evidence metadata.
        metadata = (
            ("{ key: 'services', label: 'Capabilities', icon: Server },", "js"),  # an object value
            ('{\n  "policy_id": "services",\n  "version": "1"\n}', "json"),
            ("INSERT INTO t VALUES ('apps', 'dns_iac', NULL);", "sql"),
            ('count = manifest["services"][0]', "py"),  # a subscript key
            # JSX closing tags are not regex literals: `</h2><p>{a}</p>` must not swallow a brace.
            ("export const V = ({ ok, a }) => <section>{ok ? <div><h2>{a}</h2><p>{a}</p></div> : null}</section>;\n"
             "const tabs = [{ key: 'services', label: 'Services' }];", "tsx"),
        )
        for src, ext in metadata:
            with self.subTest(metadata=src):
                self.assertEqual(scan(src, ext), set(), src)
        refused = (
            ('record = make("services", version="1", digest=value)', "py"),  # a direct call argument (root, H2)
            ('policy_ref = dict(policy_id="services", version="1")', "py"),
            ('shutil.copytree("services", "dist", dirs_exist_ok=True)', "py"),
            ('"services"', "py"),
            ('kind = "services"', "py"),
            ('def walk(root="services"):\n    pass', "py"),
            ("const p = web ? 'apps' : 'services';", "js"),
            ("const o = { dir: web ? other : 'services' };", "js"),  # a ternary branch is not an object value
            ("spawn('pytest', ['-q'], { cwd: 'services' });", "js"),  # an exec call's options are its argv's context
            ('const r = /"services"/;', "js"),  # a root inside a regex literal is not a token the classifier reads
            ('broken = (]\nTABS = ["services", "docs"]', "py"),  # a file whose brackets do not close is untrusted
            ('TABS = ["services", "docs"]\nbroken = (', "py"),
            ('p = os.path.join(ROOT, "services" + "/../../packages/shared")', "py"),  # not alone: `..` hides inside
            ('name = ("services", "docs")[i]', "py"),  # a subscripted collection is one root value, not a label list
            ("- 'services'", "yaml"),
            ('p = getattr(getattr(Path(ROOT, "services", name), "parent"), "parent") / "x"', "py"),  # rule 7 (T32)
            ('p = Path(ROOT, "services", name)\nq = p.parent.parent / "packages" / "shared"', "py"),  # rule 7 (T31)
            ("const p = `${root}/services/${up ? '..' : name}/x`;", "js"),  # H3.2: '..' in a substitution
            ('cd services\npytest ../packages/shared', "sh"),  # rule 7, raw: a `..` after a cd into a root path
            ('pytest services/b/../../packages/shared', "sh"),  # rule 7, raw: a root path and `..` on one line
            ("`${up}/..${sep}services/b`", "ts"),  # H3.2: a `..` step between substitutions
            ("f'{base}/..{os.sep}services/b'", "py"),  # H3.2 in an f-string
            ('"""\n>>> open(os.path.join(ROOT, "services", name))\n"""', "py"),  # a doctest is executed code
        )
        for src, ext in refused:
            with self.subTest(refused=src):
                with self.assertRaisesRegex(ValueError, "workspace-root reader expression"):
                    scan(src, ext)
        reads = {
            ('P = os.path.join(ROOT, "services", "b")', "py"): {"b"},
            ('P = ROOT / "services" / name', "py"): {"b"},
            ('for root in ("services", "apps"):\n    pass', "py"): {"b", "web"},
            ('walk(ROOT / "apps")', "py"): {"web"},
            ('P = Path(ROOT, "apps", name)', "py"): {"web"},
            ("const p = join(ROOT, 'services', cap, 'dist');", "js"): {"b"},
            ('for root in ("services",):\n    pass', "py"): {"b"},
            ("for (const root of ['services', 'docs']) walk(root);", "js"): {"b"},
            ("for (const [dir, job] of [['services', 'build'], ['docs', 'docs']]) run(dir, job);", "js"): {"b"},
            # A root named inside a string (prose, SQL, a glob, an f-string) is a walker read beneath it, not metadata.
            ('log.info("Walks the \'services\' tree")', "py"): {"b"},
            ('cur.execute("INSERT INTO t VALUES (\'services\')")', "py"): {"b"},
            ('for m in glob.glob("services/*/migrations"):\n    pass', "py"): {"b"},
            ('p = f"{ROOT}/services/{name}/x.json"', "py"): {"b"},
            ("const p = `${root}/services/${name}`;", "js"): {"b"},
            ('p = os.path.join(ROOT, "services", "{a,b}", "x")', "py"): {"b"},  # a brace glob is computed, not a name
            # Round 4: no rule turns a mention into nothing. Each of these reads beneath the root (wide).
            ("const tabs = ['services', 'providers', 'upstreams'];", "js"): {"b"},  # rule 8: no list exemption
            ("useQuery({\n  queryKey: ['monitoring', 'services'],\n  queryFn: load,\n});", "js"): {"b"},
            ('if kind == "services":\n    pass', "py"): {"b"},  # a comparison selects a value (H3.4)
            ("if (obligation === 'services') run();", "js"): {"b"},
            ('if part not in ("services", "docs"):\n    pass', "py"): {"b"},
            ('ctxs = {c for c in contexts if c.split("/", 1)[0] == "services"}', "py"): {"b"},
            ('"""A sweep across all of `services/` for the SDK copies."""', "py"): {"b"},  # docstrings are read (H3.6)
            ("'use strict';\nconst url = '/:org/services/:service';", "js"): {"b"},  # any root segment (H3.5)
            ('NOTE = "copied from backend/services/ in vagary-platform"', "py"): {"b"},
            ("SRC = b'name: services\\non: push\\n'", "py"): {"b"},  # a backslash always separates (H3.7)
            ('p = "{}/services/{}/x.json".format(ROOT, name)', "py"): {"b"},  # a placeholder prefix (P01)
            ('p = "services/b" + suffix', "py"): {"b"},  # a concatenated last component is partial (T21)
            ("pytest services/ -q", "sh"): {"b"},  # an unparsed file's root segment (T40)
            ('cd "$(dirname "$0")/.."  # services/r\npytest services/ -q', "sh"): {"b"},  # an anchor names no root
            ("`usage <item...> ${x} services/b`", "ts"): {"b"},  # an ellipsis in a template is not a `..` step
        }
        for (src, ext), expected in reads.items():
            with self.subTest(read=src):
                self.assertEqual(scan(src, ext), expected, src)


    # The independent review of 1.4.1 (root, 2026-10-26): 60 adversarial reader lines against this graph. A result
    # is SOUND when it reads every truth package or REFUSES (which plans FULL); it must never read less.
    REVIEW_CFG = {"schema": 1, "workspace": {"type": "declared", "packages": {
        "r": {"dir": "services/r", "deps": []}, "a": {"dir": "services/a", "deps": []},
        "b": {"dir": "services/b", "deps": []}, "nest": {"dir": "services/b/worker", "deps": []},
        "b2": {"dir": "services/b2", "deps": []}, "web": {"dir": "apps/web", "deps": []},
        "shared": {"dir": "packages/shared", "deps": []}}},
        "edge_scan": {"roots": ["services", "apps"], "reader_dirs": [], "reader_job": "root"},
        "jobs": {"root": {"packages": []}}}
    REVIEW_VECTORS = json.loads(Path(__file__).with_name("test_edges_review_vectors.json").read_text())["cases"]

    def review_scan(self, src, ext):
        repo = Path(self._td.name) / ("review-" + str(abs(hash(src)))[:10])
        for d in ("services/r", "services/a", "services/b/worker", "services/b2", "apps/web", "packages/shared"):
            (repo / d).mkdir(parents=True, exist_ok=True)
            (repo / d / "keep.txt").write_text("k\n")
        (repo / "services/r" / ("x." + ext)).write_text(src + "\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        try:
            return sorted(E.scan(repo, self.REVIEW_CFG)[0]["r"])
        except ValueError:
            return "REFUSE"

    FIXTURE_DIRS = ("services/r", "services/a", "services/b/worker", "services/b2", "apps/web", "packages/shared", ".github")

    def case_repo(self, repo, label, case):
        """The fixture a case runs in: the shared one, unless the case names its checkout's parent directory
        (`fixture_parent`, root's round-6 harness layout fx/<label>/<checkout>, 2026-11-12: C06 and C07 re-enter the
        checkout through that name) or links beside its checkout (`outside_links`) or beside the checkout's parent
        (`grand_links`): such a case gets its own <fixture_parent>/<checkout> fixture, so the parent directory is the
        name the input or the grand link uses and its links collide with no other case's."""
        if "fixture_parent" in case or "outside_links" in case or "grand_links" in case:
            return self.vector_repo(f"{case.get('fixture_parent', label)}/{case.get('checkout', 'vectors')}")
        return repo

    def vector_scan(self, repo, case, revision=False, module=None, full=False):
        """One reviewer input in the fixture repo, through the working tree or (as action.yml runs `edges.py check
        --revision`) through an immutable commit whose working tree has since changed. Root's A2 of the R-c vectors
        (2026-11-12): a case's `files` {path: text} are written too (the second tracked file a vector needs: an excluded
        hook, the sources a loader lands in) and removed after it, with the input, so no case reads another's files; its
        `unit` names what is judged, the package that owns the caller (default `r`) or a reader directory's unit
        (`readers:scripts`), so an accept vector is judged on the unit that imports, never on a bystander.
        Root's round-6 inputs (2026-11-12) add: a `files` value {"hex": ...} for bytes a JSON string cannot hold (a zip
        on the path); `outside_links` {name: target}, a link beside the checkout naming it by its directory name;
        `grand_links` {name: target}, a link beside the checkout's parent naming that parent; `env`, the case's own
        environment for the scan. Every scan runs without GITHUB_REPOSITORY (root's harness removes it, so the fixture
        never takes the runner's repository name as its own) and then with the case's `env`. `module` is the reader to
        run, the head's edges by default; the no-regression gate passes main's. `full` (root's G3 of R6-1, 2026-11-12)
        returns EVERY unit the scan produced, {("deps", package): sorted, ("readers", dir): sorted}, so the gate compares
        all of them; by default the judged unit's reading alone (unit_reading)."""
        reader = module or E
        # Root's S4 of dotgithub-86 (2026-11-12): a vector whose input re-enters the checkout through the checkout's own
        # directory name (`../vectors/packages/shared`) holds only in a fixture of that name. It names it in `checkout`,
        # asserted here, so a fixture under another name fails loudly instead of the vector testing something else.
        if "checkout" in case:
            self.assertEqual(repo.name, case["checkout"], f"this vector re-enters a checkout named {case['checkout']!r}; "
                                                          f"the fixture is {repo.name!r}")
        subprocess.run(["git", "-C", str(repo), "rm", "-rq", "--cached", "--ignore-unmatch", "services/r"], check=True)
        for f in sorted((repo / "services/r").rglob("*"), reverse=True):
            if f.is_file() and f.name != "keep.txt":
                f.unlink()
        rel = case.get("file") or "services/r/x." + case["ext"]
        extra = dict(case.get("files") or {})
        links = dict(case.get("symlinks") or {})  # {link path: target}, as the round-4 harness writes them (X08b)
        self.assertNotIn(rel, extra, "a vector's `files` cannot rewrite its own input")
        written = [rel, *sorted(extra), *sorted(links)]
        # A link beside the checkout names the checkout (its directory name); one beside the checkout's parent names
        # that parent. Asserted so a fixture under another name fails loudly (as `checkout` does above).
        beside = {}
        for name, target in dict(case.get("outside_links") or {}).items():
            self.assertEqual(target, repo.name, f"outside link {name!r} -> {target!r}: it names the checkout, which is {repo.name!r}")
            beside[repo.parent / name] = target
        for name, target in dict(case.get("grand_links") or {}).items():
            self.assertEqual(target, repo.parent.name,
                             f"grand link {name!r} -> {target!r}: it names the checkout's parent, which is {repo.parent.name!r}")
            beside[repo.parent.parent / name] = target
        # No path a vector writes may exist in the fixture, checked BEFORE the try: inside it, the cleanup would delete
        # the fixture file the guard refused to overwrite (root's K3 of #84's R4, 2026-11-12).
        for path in written:
            self.assertFalse((repo / path).exists(), f"{path}: a vector cannot write over a fixture path")
        for link in beside:
            self.assertFalse(link.exists() or link.is_symlink(), f"{link}: a vector cannot write over a path beside the fixture")
        # Root's C2 of #84 (2026-11-12): every write sits inside the try, so a failed one still cleans up.
        try:
            for path in written:
                (repo / path).parent.mkdir(parents=True, exist_ok=True)
            # `src_hex` holds raw bytes a JSON string cannot (an invalid UTF-8 byte, R7V14).
            (repo / rel).write_bytes(bytes.fromhex(case["src_hex"]) if "src_hex" in case else case["src"].encode("utf-8"))
            for path, text in extra.items():
                if isinstance(text, dict):  # {"hex": ...}: bytes a JSON string cannot hold (root's P04, a zip on the path)
                    (repo / path).write_bytes(bytes.fromhex(text["hex"]))
                else:
                    (repo / path).write_text(text)
            for path, target in links.items():
                os.symlink(target, repo / path)
            for link, target in beside.items():
                os.symlink(target, link)
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            cfg = {**self.REVIEW_CFG, **(case.get("cfg") or {})}
            rev = None
            if revision:
                # --allow-empty: the gate scans one input at a revision through both readers, and the second scan's tree
                # equals the first commit's (the cleanup emptied the index, the rewrite refilled it the same way).
                subprocess.run(["git", "-C", str(repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid",
                                "commit", "-qm", "vector", "--no-gpg-sign", "--allow-empty"], check=True)
                rev = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
                (repo / rel).write_text("# the working tree differs from the scanned revision\n")
            try:
                with patch.dict(os.environ):
                    os.environ.pop("GITHUB_REPOSITORY", None)
                    os.environ.update(case.get("env") or {})
                    deps, readers = reader.scan(repo, cfg, revision=rev)[:2]
            except ValueError as err:
                return Refusal(str(err))  # == "REFUSE"; .message is the rule that refused (root's item 7, r4 review)
            if full:
                return {**{("deps", u): sorted(v) for u, v in deps.items()},
                        **{("readers", u): sorted(v) for u, v in readers.items()}}
            return self.unit_reading(case, deps, readers)
        finally:
            # Per-case cleanup: the input and every `files` entry leave the index and the tree, and the directories they
            # alone created go too, so the next case starts from the bare fixture.
            subprocess.run(["git", "-C", str(repo), "rm", "-rq", "--cached", "--ignore-unmatch", "--", *written], check=True)
            for link in beside:
                link.unlink(missing_ok=True)
            for path in written:
                (repo / path).unlink(missing_ok=True)
                parent = (repo / path).parent
                while parent != repo and parent.relative_to(repo).as_posix() not in self.FIXTURE_DIRS and \
                        not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent

    @staticmethod
    def unit_key(case):
        """The unit a case is judged on, as a `full` reading keys it: ("deps", package) or ("readers", dir)."""
        unit = case.get("unit") or "r"
        return ("readers", unit[len("readers:"):]) if unit.startswith("readers:") else ("deps", unit)

    def unit_reading(self, case, deps, readers):
        kind, name = self.unit_key(case)
        if kind == "readers":
            # Root's B2 of #84: a reader unit the scan did not produce is a failure, never an empty reading.
            self.assertIn(name, readers, f"readers:{name}: the scan produced no such reader unit")
            return sorted(readers[name])
        return sorted(deps[name])

    def vector_repo(self, name):
        repo = Path(self._td.name) / name
        for d in ("services/r", "services/a", "services/b/worker", "services/b2", "apps/web", "packages/shared", ".github"):
            (repo / d).mkdir(parents=True, exist_ok=True)
            (repo / d / "keep.txt").write_text("k\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        return repo

    def judge(self, label, case, got):
        truth, expect = case["truth"], case["expect"]
        if "known_fail_open" in case:
            # A dated known fail-open reads below its truth by ruling: its pin, not its truth, is judged, either way. Only
            # a label in the closed KNOWN_FAIL_OPEN map is (root's B1 of dotgithub-86): a pin added to any other vector
            # fails here, whatever it says.
            self.assertIn(label, KNOWN_FAIL_OPEN, f"{label}: a known_fail_open pin outside the closed KNOWN_FAIL_OPEN map")
            pin = case["known_fail_open"]
            self.assertEqual(got, pin["today"], f"{label}: known fail-open {pin['gap']} read {got}, pinned "
                                                f"{pin['today']}; once it reads its truth {truth} this commit removes the pin")
        elif expect == "refuse":
            self.assertEqual(got, "REFUSE", label)
            if "expected_rule" in case:
                # Root's item 7 and ruling (c) of the R-c r4 review (2026-11-12): a refuse names the rule it expects, as
                # a substring of the reader's ValueError, so a refusal for another reason (a config-shape error, a
                # neighbouring rule) fails here. A case without `expected_rule` keeps the bare REFUSE judgment.
                self.assert_rule(label, got, case["expected_rule"], "expected_rule")
        elif expect == "residual":
            # A named residual reads less than its truth by ruling; its reading when pinned is recorded so that one
            # reading even less (or more) fails here until the pin is re-derived on purpose.
            self.assertEqual(got, case["reads"], f"{label}: a residual's reading moved from its pin")
        else:
            # Root's A1 of the R-c vectors (2026-11-12): an accept vector with an empty truth proves nothing (a reading
            # of [] satisfies it), so one is admitted only as a declared precision control, which asserts the absence.
            self.assertTrue(truth or case.get("control") is True,
                            f"{label}: an accept vector with truth [] proves nothing; a precision control says `control: true`")
            if case.get("control") is True:
                # Root's B2 of #84 (2026-11-12): `control: true` is a check, not a label: a control pins its reading (as
                # a residual does), so a control that starts reading, or refusing, fails until the pin is re-derived.
                self.assertEqual(got, case["reads"], f"{label}: a control's reading moved from its pin")
            self.assertTrue(got == "REFUSE" or set(truth) <= set(got), f"{label}: read {got}, truth {truth}")
            if expect == "read":
                self.assertNotEqual(got, "REFUSE", f"{label}: a resolvable read must not refuse")

    def assert_rule(self, label, got, rule, field):
        """`got` refused, and for the rule `rule` names: a substring of the reader's ValueError (ruling (c))."""
        self.assertTrue(isinstance(rule, str) and rule.strip(),
                        f"{label}: `{field}` must be a non-empty string; an empty fragment matches every refusal")
        # Root's S2 of dotgithub-86 (2026-11-12): a fragment the catch-all refusal also prints passes on the catch-all,
        # so it cannot tell the rule it names from it.
        self.assertEqual([part for part in catch_all_fragments() if rule in part], [],
                         f"{label}: `{field}` {rule!r} is text the catch-all refusal also prints; pin a clause of the rule "
                         "itself")
        self.assertIsInstance(got, Refusal, f"{label}: no refusal message was recorded to judge `{field}` against")
        self.assertIn(rule, got.message, f"{label}: refused for another rule: `{field}` {rule!r} is not in the "
                                         f"refusal {got.message[:200]!r}")
        self.assertIsNone(re.fullmatch(catch_all_pattern(), got.message, re.S),
                          f"{label}: the refusal is the catch-all ({got.message[:200]!r}); `{field}` {rule!r} matched its "
                          "text, not its rule's")

    def assert_known_fail_open_pins(self, vectors, on):
        """The data-only checks on every `known_fail_open` vector, against the date `on`: a label of the closed
        KNOWN_FAIL_OPEN map with its gap, its `until` exactly KNOWN_FAIL_OPEN_UNTIL, a read with a truth, never a control
        or a residual, pinned below its truth, not past the date; and the map and the pinned vectors equal both ways."""
        until = datetime.date.fromisoformat(KNOWN_FAIL_OPEN_UNTIL)
        pinned = {}
        for label, case in sorted(vectors.items()):
            if "known_fail_open" not in case:
                continue
            pin = case["known_fail_open"]
            # Outside the subTest: a failed case still counts, so only a drop or an addition trips the both-ways check.
            pinned[label] = pin.get("gap") if isinstance(pin, dict) else None
            with self.subTest(f"{label}:known_fail_open"):
                self.assertEqual(sorted(pin), ["gap", "record", "today", "until"], f"{label}: known_fail_open's keys")
                self.assertIn(label, KNOWN_FAIL_OPEN, f"{label}: a known_fail_open pin outside the closed KNOWN_FAIL_OPEN map")
                self.assertEqual(pin["gap"], KNOWN_FAIL_OPEN[label],
                                 f"{label}: pinned gap {pin['gap']!r}, KNOWN_FAIL_OPEN says {KNOWN_FAIL_OPEN[label]!r}")
                self.assertEqual(pin["until"], KNOWN_FAIL_OPEN_UNTIL,
                                 f"{label}: until {pin['until']!r}; every pin carries KNOWN_FAIL_OPEN_UNTIL, no later date")
                # expect read, so never a residual: the residual list is exactly the `expect: residual` labels.
                self.assertEqual(case["expect"], "read", f"{label}: a known fail-open is a read, not a residual or a refuse")
                self.assertNotEqual(case.get("control"), True, f"{label}: a case is a control or a known fail-open, not both")
                self.assertTrue(case["truth"] and isinstance(pin["today"], list) and
                                not set(case["truth"]) <= set(pin["today"]),
                                f"{label}: a known fail-open pins a reading below a non-empty truth, not {pin['today']}")
                if on >= until or on >= datetime.date.fromisoformat(pin["until"]):
                    self.fail(f"{label}: known fail-open {pin['gap']} past its date {KNOWN_FAIL_OPEN_UNTIL}")
        # Membership both ways, each failure naming its side, then the gaps (root's B1 of dotgithub-86).
        self.assertEqual(sorted(set(pinned) - set(KNOWN_FAIL_OPEN)), [],
                         "a known_fail_open pin outside the closed KNOWN_FAIL_OPEN map")
        self.assertEqual(sorted(set(KNOWN_FAIL_OPEN) - set(pinned)), [],
                         "a stale KNOWN_FAIL_OPEN entry: it names no review vector carrying its known_fail_open pin")
        self.assertEqual(pinned, KNOWN_FAIL_OPEN, "a pinned vector's known_fail_open.gap differs from KNOWN_FAIL_OPEN")

    # Ruling (c) of root's R-c r4 review (2026-11-12): how a vector opts in. A case carrying `ablation` is always judged
    # by test_review_vector_ablations_read_no_truth_and_refuses_pin_their_rule. A case that also says `"r5": true` makes
    # the round-5 schema mandatory for itself: an accept (`expect` read or sound, a control included) must carry
    # `ablation` and `ablation_kind`, a refuse must carry `expected_rule`. The pre-r5 vectors carry neither key and keep
    # passing unchanged; an r5 vector cannot drop its ablation or its rule silently.
    ABLATION_KINDS = ("construct+declaration", "declaration")
    ABLATION_KEYS = {"src", "cfg", "files", "symlinks"}

    def ablation_input(self, case):
        """The ablated case as vector_scan reads it, built as the r3/r4 measurer built it (vectors-rc-driver3.py
        run_ablation): `src` is the ablation's (the case's `src_hex` is dropped, or vector_scan would scan the original
        bytes); `files` and `symlinks` are the ablation's when it carries them, else the case's own; `cfg` is the
        ablation's or NONE (the fixture's REVIEW_CFG), never the case's, which would put back the declaration being
        ablated; `ext`, `file` and `unit` stay the case's, so the ablation is judged on the unit the case is."""
        ablation = case["ablation"]
        ablated = {key: value for key, value in case.items() if key in ("ext", "file", "unit", "files", "symlinks")}
        ablated["src"] = ablation["src"]
        for key in ("files", "symlinks", "cfg"):
            if key in ablation:
                ablated[key] = ablation[key]
        return ablated

    def test_review_vector_ablations_read_no_truth_and_refuses_pin_their_rule(self):
        """Ruling (c) of root's R-c r4 review (2026-11-12), items 6 and 7: every accept's ablation runs, controls included
        (the r4 measurer skipped controls, so the one `declaration` ablation never ran). A construct+declaration
        ablation must READ (a refusal is not ok) and read NO unit of the case's truth, or the vector does not test the
        construct it names; a declaration-only ablation must REFUSE for its `ablation_expected_rule`."""
        repo = self.vector_repo("ablations")
        judged = 0
        for label, case in sorted(self.REVIEW_VECTORS.items()):
            accept = case["expect"] not in ("refuse", "residual")
            with self.subTest(f"{label}:ablation"):
                if case.get("r5") is True:
                    if case["expect"] == "refuse":
                        self.assertIn("expected_rule", case, f"{label}: an r5 refuse pins its rule in `expected_rule`")
                    elif accept:
                        self.assertIn("ablation", case, f"{label}: an r5 accept (a control too) carries an `ablation`")
                if "ablation" not in case:
                    self.assertFalse({"ablation_kind", "ablation_expected_rule"} & set(case),
                                     f"{label}: an ablation_kind or ablation_expected_rule without an `ablation`")
                    continue
                self.assertTrue(accept, f"{label}: an ablation is judged on an accept only, not expect {case['expect']!r}")
                ablation, kind = case["ablation"], case.get("ablation_kind")
                self.assertIsInstance(ablation, dict, f"{label}: an ablation is an object")
                self.assertIsInstance(ablation.get("src"), str, f"{label}: an ablation carries its `src`")
                self.assertEqual(sorted(set(ablation) - self.ABLATION_KEYS), [],
                                 f"{label}: an ablation carries only {sorted(self.ABLATION_KEYS)}; another key is not read")
                self.assertIn(kind, self.ABLATION_KINDS, f"{label}: ablation_kind {kind!r} is not one of {self.ABLATION_KINDS}")
                got = self.vector_scan(repo, self.ablation_input(case))
                judged += 1
                if kind == "construct+declaration":
                    self.assertNotIn("ablation_expected_rule", case,
                                     f"{label}: ablation_expected_rule belongs to a declaration-only ablation")
                    if isinstance(got, Refusal):
                        self.fail(f"{label}: the construct+declaration ablation refused ({got.message[:200]!r}); with its "
                                  f"construct and declaration removed it must READ")
                    self.assertEqual(sorted(set(case["truth"]) & set(got)), [],
                                     f"{label}: the ablation (construct and declaration removed) still reads truth units, "
                                     f"read {got}: the vector does not test the construct it names")
                else:
                    self.assertEqual(got, "REFUSE", f"{label}: the declaration-only ablation read {got}; it must refuse")
                    self.assertIn("ablation_expected_rule", case, f"{label}: a declaration-only ablation pins its rule")
                    self.assert_rule(label, got, case["ablation_expected_rule"], "ablation_expected_rule")
        # A floor inside the gate: with no ablation in the vectors this test asserted nothing, so it fails instead.
        self.assertGreater(judged, 0, "the ablation assertion matched nothing: no review vector carries an `ablation`")

    def assert_designed_red(self, which, red):
        """The labels whose judgement failed (`red`: label -> why) must EQUAL DESIGNED_RED[which] by name. Three ways to
        fail, each naming its labels: a label no vector carries (a renamed or dropped vector leaves a stale pin), a NEW red
        (a 47th: the real regression a designed-red suite would otherwise hide), and a label gone GREEN (a slice read it
        and must move it out of DESIGNED_RED in the same commit, so the set never pins more than the head's reading)."""
        designed = DESIGNED_RED[which]
        self.assertEqual(sorted(label for label in designed if self.vector_of(label) not in self.REVIEW_VECTORS), [],
                         f"DESIGNED_RED[{which!r}] names labels no review vector carries")
        new = sorted(set(red) - designed)
        green = sorted(designed - set(red))
        self.assertEqual(new, [], f"NEW red outside DESIGNED_RED[{which!r}] ({len(new)}): "
                                  + "; ".join(f"{label}: {red[label][:300]}" for label in new))
        self.assertEqual(green, [], f"designed-red labels now GREEN ({len(green)}), move them out of DESIGNED_RED[{which!r}]"
                                    f" in this commit: {green}")

    @staticmethod
    def vector_of(label):
        """The review vector a red label names: the gate's ablation leg reds `<label>:ablation`, its revision leg
        `<label>@revision`; every other label is the vector itself."""
        return label.split(":ablation")[0].split("@revision")[0]

    def test_designed_red_pin_fails_by_name_three_ways(self):
        """assert_designed_red is not vacuous: the designed set itself passes; a 47th label, a designed label gone green
        and a pin naming no vector each fail, naming the label. DESIGNED_RED's gate set is within its review set (the
        nine fail both tests), and both sets name only vectors."""
        for which in DESIGNED_RED:
            self.assert_designed_red(which, {label: "designed" for label in DESIGNED_RED[which]})
        self.assertTrue({label for label in DESIGNED_RED["gate"] if label == self.vector_of(label)} <= DESIGNED_RED["review"],
                        "the gate's tree-leg reds are review reds too")
        review = {label: "designed" for label in DESIGNED_RED["review"]}
        with self.assertRaisesRegex(AssertionError, r"NEW red outside DESIGNED_RED\['review'\] \(1\): A12_dict_value_as_path: why"):
            self.assert_designed_red("review", {**review, "A12_dict_value_as_path": "why"})
        gone = sorted(DESIGNED_RED["review"])[0]
        with self.assertRaisesRegex(AssertionError, rf"now GREEN \(1\).*{gone}"):
            self.assert_designed_red("review", {k: v for k, v in review.items() if k != gone})
        with patch.dict(DESIGNED_RED, {"review": DESIGNED_RED["review"] | {"ZZ_no_such_vector"}}):
            with self.assertRaisesRegex(AssertionError, r"names labels no review vector carries"):
                self.assert_designed_red("review", {**review, "ZZ_no_such_vector": "x"})

    def test_review_vectors_read_their_truth_or_refuse(self):
        """Every input of root's three independent reviews, spine's own probes and the round-4 rule-7 vectors: none may
        read less than its truth without refusing, and those resolvable today must keep reading. Exempt: A12/N08/N11
        (object values and keys, the ratified metadata), T19/T36/T37 (lexical limits), M5/M6/V48 (a literal root read
        does not start taint: measured +11 vagary-core refusals) and V45-V47 (heads by tuple slicing, a regex or
        os.path.split), and the fifth and sixth reviews' inputs outside README rule 4's closed list, all named
        residuals; and #84's dated known fail-opens (KNOWN_FAIL_OPEN), each judged by its pin until its date. The closed
        lists these rest on are test_review_vector_closed_lists_hold's, so they report apart from any vector's reading."""
        repo = self.vector_repo("vectors")
        red = {}
        for label, case in sorted(self.REVIEW_VECTORS.items()):
            with self.subTest(label):
                try:
                    self.judge(label, case, self.vector_scan(self.case_repo(repo, label, case), case))
                except AssertionError as exc:
                    red[label] = str(exc)
        self.assert_designed_red("review", red)
        self.assertEqual(sorted(k for k, c in self.REVIEW_VECTORS.items() if c["expect"] == "residual" and "reads" not in c),
                         [], "every residual vector pins its reading")
        # Root's B2 of #84 (2026-11-12): the precision controls are a closed list and each pins its reading, so a new
        # vector cannot take `control: true` (and its truth-[] exemption) silently.
        self.assertEqual(sorted(k for k, c in self.REVIEW_VECTORS.items() if c.get("control") is True and "reads" not in c),
                         [], "every precision control pins its reading")
        self.assertEqual(sorted(k for k, c in self.REVIEW_VECTORS.items() if c["expect"] == "residual"),
                         [
                          "A12_dict_value_as_path", "M5_py_literal_join_then_parent_parent",
                          "M6_py_literal_slash_then_parents", "N08_dict_values_walked", "N11_dict_key_walked",
                          "R5V01_py_subprocess_module_alias", "R5V02_py_from_subprocess_import_run",
                          "R5V03_py_command_string_via_variable", "R5V04_py_asyncio_create_subprocess_shell",
                          "R5V07_js_execaCommand", "R5V08_js_child_process_destructured_alias",
                          "R5V17_yaml_key_is_project_dir", "R5V24_py_dirname_alias_inline_comment",
                          "R5V25_py_dirname_alias_tuple", "R5V26_js_require_dirname_alias",
                          "R5V27_py_parent_name_concat_dots", "R5V28_py_parent_name_joined_dots",
                          "R5V29_py_parent_name_path_dotdot", "R5V30_py_parent_name_fstring",
                          "R5V31_py_parent_name_in_substitution", "R5V32_py_adjacent_dot_literals_in_subst",
                          "R5V33_py_joined_dots_in_subst", "R5V35_py_cached_property",
                          "R5V36_py_property_with_comment", "R5V37_py_function_ref_via_assignment",
                          "R5V38_py_getattr_literal_method", "R5V39_py_factory_closure", "R5V40_py_deque_appendleft",
                          "R5V41_js_object_assign", "R6V02_yml_key_still_metadata_control", "R6V03_uppercase_YML_ext",
                          "R6V18_pkg_husky_hooks_not_scripts", "R6V24_chdir_then_path_cwd_parent",
                          "R6V25_chdir_then_fstring_dotdot_end",
                          "R6_residual_reexported_alias_reads_below_truth", "R84_B11_nested_fn_param_shadow",
                          "R84_S08_param_shadow_other_assign",
                          # Root's r4 item 11 (R-c r5) RC1A_residual_generated_cwd_directory left this list in the
                          # round-5 fix (2026-11-12): its tracked start lands at the root and refuses (B3).
                          "T19_partial_split_root",
                          "T36_computed_prefix_not_repo_root",
                          "T37_fstring_computed_prefix_not_root", "V45_py_parts_slice_head", "V46_py_regex_head",
                          "V47_py_split_head_contract", "V48_py_literal_read_then_parent"])

    def pinned_main_source(self, head_source, pin):
        """The text of MAIN's edges.py the gate compares the head's with: the blob `pin` (MAIN_EDGES_BLOB) from this
        clone's object store. Fails, never skips, when the clone cannot show it (origin/main absent: planner-tests checks
        out with fetch-depth 0), when main's edges.py moved under this branch (re-derive the gate, re-pin), when the head
        IS main's reader but the pin names no edges.py main ever carried, or when the pinned text equals the head's (the
        gate would compare a reader with itself). `head_source` is the head reader's text; main_reader passes the real
        one, test_main_pin_resolves_when_the_head_is_main drives the head == main branch with main's own.
        Root's G1 of R6-1 (2026-11-12): `git -C <action dir> rev-list -- <path>` resolves the path against the action
        directory and returned 0 commits for a repo-root path, so the head == main branch could never pass (the day #86
        lands, red on main and on every PR leaving edges.py alone): the pathspec is `:(top)`-anchored."""
        here = Path(E.__file__).resolve().parent
        git = ["git", "-C", str(here)]
        head_blob = subprocess.check_output([*git, "hash-object", "--stdin"], input=head_source).decode().strip()
        live = subprocess.run([*git, "rev-parse", "--verify", "-q", f"origin/main:{MAIN_EDGES_PATH}"],
                              capture_output=True, text=True)
        self.assertEqual(live.returncode, 0, "origin/main is not in this clone, so the gate cannot read main's reader: "
                                             "planner-tests checks out with fetch-depth 0")
        live_blob = live.stdout.strip()
        if live_blob != head_blob:
            self.assertEqual(live_blob, pin, "main's edges.py moved under this branch: re-derive the no-regression gate "
                                             "against it and re-pin MAIN_EDGES_BLOB")
        else:
            # The head IS main's reader (main itself, or a branch that changes no reader): the pin must name a former
            # main edges.py, so the gate still compares two real readers and the pin cannot point at nothing.
            former = self.former_main_blobs()
            self.assertIn(pin, former, "MAIN_EDGES_BLOB names no edges.py main ever carried")
        shown = subprocess.run([*git, "cat-file", "-p", pin], capture_output=True)
        self.assertEqual(shown.returncode, 0, f"the pinned main blob {pin} is not in this clone's object store")
        self.assertNotEqual(shown.stdout, head_source, "floor: the pinned main reader and the head's are the same source, "
                                                       "the gate would compare a reader with itself")
        return shown.stdout

    def former_main_blobs(self):
        """Every blob of MAIN_EDGES_PATH origin/main ever carried, in history order (the live one first): the set the
        head == main branch of pinned_main_source resolves MAIN_EDGES_BLOB in. The pathspec is anchored at the top of
        the work tree (`:(top)`), so the command reads the same from the action directory as from the repo root."""
        here = Path(E.__file__).resolve().parent
        git = ["git", "-C", str(here)]
        commits = subprocess.check_output([*git, "rev-list", "origin/main", "--", f":(top){MAIN_EDGES_PATH}"],
                                          text=True).split()
        blobs = []
        for c in commits:
            blob = subprocess.check_output([*git, "rev-parse", f"{c}:{MAIN_EDGES_PATH}"], text=True).strip()
            if blob not in blobs:
                blobs.append(blob)
        return blobs

    def main_reader(self):
        """MAIN's edges.py as a module, from the pinned blob MAIN_EDGES_BLOB (pinned_main_source). The module's __file__
        is a path beside plan.py that is never written, so main's lazy `_plan()` resolves to the plan.py this suite
        already imported."""
        here = Path(E.__file__).resolve().parent
        text = self.pinned_main_source(Path(E.__file__).read_bytes(), MAIN_EDGES_BLOB)
        module = types.ModuleType("edges_main")
        module.__file__ = str(here / f"edges_main_{MAIN_EDGES_BLOB[:12]}.py")
        exec(compile(text, module.__file__, "exec"), module.__dict__)
        module.today = E.today
        return module

    def test_main_pin_resolves_when_the_head_is_main(self):
        """Root's G1 of R6-1 (2026-11-12): the head == main branch of the pin, driven. With main's own edges.py as the
        head source and a FORMER main blob as the pin, pinned_main_source resolves the pin (it is in origin/main's
        history of the file) and returns its text; with a blob main never carried (the head's own, while it differs
        from main's) it fails naming the pin; and the live pin MAIN_EDGES_BLOB is itself a blob main carried. The
        history read from the action directory holds more than one blob: the 0-commit read of the G1 bug fails here."""
        here = Path(E.__file__).resolve().parent
        git = ["git", "-C", str(here)]
        former = self.former_main_blobs()
        self.assertGreater(len(former), 1, f"origin/main's history of {MAIN_EDGES_PATH} read from the action directory "
                                           f"holds {len(former)} blob(s): the pathspec is not anchored at the top")
        self.assertIn(MAIN_EDGES_BLOB, former, "MAIN_EDGES_BLOB names no edges.py main ever carried")
        live_blob = subprocess.check_output([*git, "rev-parse", f"origin/main:{MAIN_EDGES_PATH}"], text=True).strip()
        self.assertEqual(former[0], live_blob)
        main_source = subprocess.check_output([*git, "cat-file", "-p", live_blob])
        older = next(blob for blob in former if blob != live_blob)
        self.assertEqual(self.pinned_main_source(main_source, older),
                         subprocess.check_output([*git, "cat-file", "-p", older]))
        head_blob = subprocess.check_output([*git, "hash-object", "--", E.__file__], text=True).strip()
        if head_blob not in former:  # the head changes the reader (this branch does): a pin main never carried fails
            with self.assertRaisesRegex(AssertionError, "names no edges.py main ever carried"):
                self.pinned_main_source(main_source, head_blob)
        # The pin equal to the head source is the floor, not a resolution.
        with self.assertRaisesRegex(AssertionError, "compare a reader with itself"):
            self.pinned_main_source(main_source, live_blob)

    # Root's round-6 inputs where main refuses and the head reads its truth: the control proving the two readers the gate
    # compares differ, so the gate cannot pass by loading the head twice.
    GATE_CONTROL = "G01_literal_unowned_dir_under_root"

    # The review vectors the --revision path is driven on (test_review_vectors_hold_at_a_revision): the round-2 cases
    # whose lines span or shift, positive controls that must READ, and #84's B1 brace-named tops. The no-regression gate
    # scans the same closed list through both readers at a revision.
    REVISION_LABELS = ("N10_py_ternary_in_join", "N12_fstring_sql_with_nested_join", "N26_subprocess_multiline_list_own_line",
                       "N27_subprocess_list_opened_own_line", "N31_js_spawn_multiline", "N42_parent_after_Path_call",
                       "N52_formfeed_above_multiline_join", "N53_u2028_in_js_string_above_join",
                       "X01_formfeed_index_overrun_crash", "X02_lone_cr_above_multiline_join",
                       "A01_multiline_join_computed", "A02_multiline_join_literal", "A03_multiline_args_same_line",
                       "W07_multiline_roots",
                       # Root's B1 of #84: a top literally named `{tpl}` / `${tpl}` refuses on the --revision path too.
                       "R84_Z01_brace_named_top_dir", "R84_Z02_dollar_brace_named_top_dir")

    def leg_fixture(self, repo, label, case, leg):
        """case_repo for the gate's ablation and revision legs: a case that names its own fixture (fixture_parent,
        checkout, links beside it) gets one under `<leg>/`, apart from the tree leg's fixture of the same name."""
        if "fixture_parent" in case or "outside_links" in case or "grand_links" in case or "checkout" in case:
            case = {**case, "fixture_parent": f"{leg}/{case.get('fixture_parent', label)}"}
        return self.case_repo(repo, label, case)

    def gate_compare(self, label, case, truth, main_full, head_full, compared, red):
        """One input under both readers, main's `main_full` beside the head's `head_full` (each "REFUSE" or a `full`
        reading of every unit). Where main REFUSES (or produced no judged unit), the head refuses or reads its truth.
        Where main READS the judged unit, the head refuses, reads its truth, or reads everything main reads. Root's G3
        of R6-1 (RULED 2026-11-12): when BOTH readers read, EVERY unit of deps and readers is compared, the judged unit
        at truth excepted: a head below main on any unit is a regression (vector_scan returning the judged unit alone
        is how the rsub case hid). `red` gains label -> why; `compared` counts what was compared. Returns whether the
        all-units leg alone made the label red (the verdict change root asked to be counted)."""
        key = self.unit_key(case)
        main_got = main_full if main_full == "REFUSE" else main_full.get(key)  # None: main produced no such unit
        head_got = head_full if head_full == "REFUSE" else head_full.get(key)
        if head_got is None:
            red[label] = f"the head's scan produced no unit {key}"  # root's B2 of #84: never an empty reading
            return False
        at = head_got != "REFUSE" and truth is not None and truth <= set(head_got)
        if main_got == "REFUSE" or main_got is None:
            compared["main refuses" if main_got == "REFUSE" else "main produced no such unit"] += 1
            if not (head_got == "REFUSE" or at):
                red[label] = (f"main refuses, the head reads {head_got} below its truth {sorted(truth)}: a regression "
                              f"against main's reader")
        else:
            compared["main reads"] += 1
            if not (head_got == "REFUSE" or at or set(main_got) <= set(head_got)):
                red[label] = (f"main reads {main_got}, the head reads {head_got}: below its truth {sorted(truth)} and "
                              f"below main's reading")
        if main_full == "REFUSE" or head_full == "REFUSE":
            return False
        compared["both read"] += 1
        below = {}
        for unit, main_units in sorted(main_full.items()):
            if unit != key:
                compared["other units"] += 1
            if unit == key and at:
                continue
            if not set(main_units) <= set(head_full.get(unit, [])):
                below[unit] = (main_units, head_full.get(unit, []))
        if below and label not in red:
            red[label] = "all-units: main reads more than the head on " + "; ".join(
                f"{kind}:{name} main {m} head {h}" for (kind, name), (m, h) in sorted(below.items()))
            return True
        return False

    def test_r6_no_regression_against_main_reader(self):
        """Root's R6 ruling (1) of dotgithub-86 (16:13 2026-11-12), design line 7 accepted 16:44: main's reader beside
        the head's on every review vector, root's 111 included (the rule: gate_compare). Three legs: every vector through
        the working tree; every accept's ablation (ablation_input, judged with no truth: an ablation reads none of it);
        REVISION_LABELS through an immutable commit (the --revision path action.yml runs). Floors inside the gate: main's
        source differs from the head's; at least one main-refuse, one main-read and one both-read case was compared, and
        the all-units leg compared units beyond the judged one; every ablation and every REVISION_LABELS case was
        compared; GATE_CONTROL refuses on main and reads at truth on the head. The all-units verdict changes (labels red
        by that leg alone) are printed with the counts for the push line."""
        main = self.main_reader()
        repo = self.vector_repo("gate/vectors")  # named as the shared fixture is: eight S4 cases assert `checkout`
        compared = {"main refuses": 0, "main reads": 0, "main produced no such unit": 0, "both read": 0, "other units": 0,
                    "ablations": 0, "at a revision": 0}
        control = None
        red = {}
        all_units_only = []
        for label, case in sorted(self.REVIEW_VECTORS.items()):
            with self.subTest(label):
                fixture = self.case_repo(repo, label, case)
                main_full = self.vector_scan(fixture, case, module=main, full=True)
                head_full = self.vector_scan(fixture, case, full=True)
                truth = set(case["truth"]) if isinstance(case["truth"], list) else None  # "REFUSE": no reading is at truth
                if label == self.GATE_CONTROL:
                    head_got = head_full if head_full == "REFUSE" else head_full.get(self.unit_key(case))
                    main_got = main_full if main_full == "REFUSE" else main_full.get(self.unit_key(case))
                    control = (main_got, head_got != "REFUSE" and head_got is not None and truth <= set(head_got))
                if self.gate_compare(label, case, truth, main_full, head_full, compared, red):
                    all_units_only.append(label)
        ablations = self.vector_repo("gate-ablations/vectors")
        for label, case in sorted(self.REVIEW_VECTORS.items()):
            if "ablation" not in case:
                continue
            with self.subTest(f"{label}:ablation"):
                ablated = self.ablation_input(case)
                fixture = self.leg_fixture(ablations, label, ablated, "gate-ablations")
                main_full = self.vector_scan(fixture, ablated, module=main, full=True)
                head_full = self.vector_scan(fixture, ablated, full=True)
                compared["ablations"] += 1
                if self.gate_compare(f"{label}:ablation", ablated, set(), main_full, head_full, compared, red):
                    all_units_only.append(f"{label}:ablation")
        revision = self.vector_repo("gate-revision/vectors")
        for label in self.REVISION_LABELS:
            with self.subTest(f"{label}@revision"):
                case = self.REVIEW_VECTORS[label]
                fixture = self.leg_fixture(revision, label, case, "gate-revision")
                main_full = self.vector_scan(fixture, case, revision=True, module=main, full=True)
                head_full = self.vector_scan(fixture, case, revision=True, full=True)
                compared["at a revision"] += 1
                truth = set(case["truth"]) if isinstance(case["truth"], list) else None
                if self.gate_compare(f"{label}@revision", case, truth, main_full, head_full, compared, red):
                    all_units_only.append(f"{label}@revision")
        print(f"\nno-regression gate: compared {compared}; red {len(red)}; all-units verdict changes "
              f"{len(all_units_only)}: {all_units_only}", file=sys.stderr)
        self.assert_designed_red("gate", red)
        self.assertGreater(compared["main refuses"], 0, "floor: no vector main refuses was compared")
        self.assertGreater(compared["main reads"], 0, "floor: no vector main reads was compared")
        self.assertGreater(compared["both read"], 0, "floor: no vector both readers read was compared")
        self.assertGreater(compared["other units"], 0, "floor: the all-units leg compared no unit beyond the judged one")
        self.assertEqual(compared["ablations"], sum(1 for c in self.REVIEW_VECTORS.values() if "ablation" in c))
        self.assertGreater(compared["ablations"], 0, "floor: no ablation was compared")
        self.assertEqual(compared["at a revision"], len(self.REVISION_LABELS))
        self.assertEqual(control, ("REFUSE", True),
                         f"floor: {self.GATE_CONTROL} must refuse on main and read its truth on the head, got {control}")

    def test_review_vector_closed_lists_hold(self):
        """The data-only closed lists the review vectors rest on, apart from any reading: REVIEW_CONTROLS and
        KNOWN_FAIL_OPEN both ways, the pins dated KNOWN_FAIL_OPEN_UNTIL, the `"r5": true` set (S1), and no
        `expected_rule` / `ablation_expected_rule` the catch-all refusal also prints, against the template edges.py
        really raises (S2; root's dotgithub-86 review, 2026-11-12)."""
        vectors = self.REVIEW_VECTORS
        # Ruling (c) of root's R-c r4 review (2026-11-12): membership is asserted both ways, each failure naming its side.
        controls = {k for k, c in vectors.items() if c.get("control") is True}
        self.assertEqual(len(set(REVIEW_CONTROLS)), len(REVIEW_CONTROLS), "REVIEW_CONTROLS names a label twice")
        self.assertEqual(sorted(controls - set(REVIEW_CONTROLS)), [],
                         "a precision control outside the closed list: add it to REVIEW_CONTROLS, with its pinned reading")
        self.assertEqual(sorted(set(REVIEW_CONTROLS) - controls), [],
                         "a stale REVIEW_CONTROLS entry: it names no `control: true` review vector")
        # The real UTC date, not the suite's frozen E.today() (2026-10-29, top of file): every `until` falls after it,
        # so against it a dated pin could never expire.
        self.assert_known_fail_open_pins(vectors, datetime.datetime.now(datetime.timezone.utc).date())
        # S1: the r5 set is closed, by count and by label.
        r5 = {k for k, c in vectors.items() if c.get("r5") is True}
        self.assertEqual(sorted(k for k, c in vectors.items() if "r5" in c and c["r5"] is not True), [],
                         "`r5` is `true` or absent")
        self.assertEqual(len(r5), R5_VECTOR_COUNT, f"{len(r5)} vectors carry `\"r5\": true`, R5_VECTOR_COUNT says "
                                                   f"{R5_VECTOR_COUNT}: a drop or an addition is an edit there")
        self.assertEqual(sorted(k for k in RC_LABELS_BEFORE_R5 if k not in vectors), [],
                         "a stale RC_LABELS_BEFORE_R5 entry: it names no review vector")
        expected_r5 = {k for k in vectors if k.startswith(R5_PREFIX) and k not in RC_LABELS_BEFORE_R5}
        self.assertEqual(sorted(expected_r5 - r5), [], f"an {R5_PREFIX} vector without `\"r5\": true`")
        self.assertEqual(sorted(r5 - expected_r5), [], f"an `\"r5\": true` vector outside the {R5_PREFIX} labels")
        # S2: the catch-all template is edges.py's own (one raise, its two `what`s), so the check below is not vacuous.
        source = Path(E.__file__).read_text()
        head, tail = CATCH_ALL_REFUSAL.split("in {where}")
        self.assertRegex(source, re.escape(f'f"{head}"') + r"\s*" + re.escape('f"in {where}"'),
                         "CATCH_ALL_REFUSAL is no longer the template edges.py raises: re-derive it")
        self.assertEqual(tail, "")
        self.assertIn('what: str = "sys.path entry"', source, "CATCH_ALL_WHATS: apply_entry's default `what` moved")
        self.assertIn('"pytest pythonpath entry"', source, "CATCH_ALL_WHATS: the pytest pythonpath `what` moved")
        fragments = catch_all_fragments()
        rules = {(k, field): c[field] for k, c in vectors.items()
                 for field in ("expected_rule", "ablation_expected_rule") if field in c}
        pinned = sorted(f"{k}:{field}" for (k, field), rule in rules.items() if R5_SYS_PATH_RULE in rule)
        self.assertEqual(len(pinned), R5_SYS_PATH_RULE_PINS,
                         f"{len(pinned)} pins name {R5_SYS_PATH_RULE!r}, R5_SYS_PATH_RULE_PINS says {R5_SYS_PATH_RULE_PINS}: "
                         "a drop or an addition is an edit there")
        self.assertIn(f"unresolved ({R5_SYS_PATH_RULE} `", source,
                      "R5_SYS_PATH_RULE is no longer the text edges.py raises: re-derive it")
        # Slices 2 and 3 and R6-2: each rule's pin count by equality, and its own raise site in edges.py.
        for site in R6_CAPABILITY_SITES:
            self.assertIn(site, source, f"R6_CAPABILITY_SITES: {site!r} is no longer in edges.py: re-derive it")
        for pins_name, pins in (("RC1B_RULE_PINS", RC1B_RULE_PINS), ("RC1A_RULE_PINS", RC1A_RULE_PINS),
                                ("RC1A_FIX_RULE_PINS", RC1A_FIX_RULE_PINS),
                                ("R6_CAPABILITY_RULE_PINS",
                                 {R6_CAPABILITY_RULE: (R6_CAPABILITY_RULE_PINS, R6_CAPABILITY_SITES[1])}),
                                ("R5F_RULE_PINS", {rule: pin[:2] for rule, pin in R5F_RULE_PINS.items()})):
            for rule, (count, site) in pins.items():
                named = sorted(f"{k}:{field}" for (k, field), pinned_rule in rules.items() if rule in pinned_rule)
                self.assertEqual(len(named), count, f"{len(named)} pins name {rule!r}, {pins_name} says {count}: a "
                                                    f"drop or an addition is an edit there")
                self.assertIn(site, source,
                              f"{pins_name}: the raise site of {rule!r} is no longer in edges.py: re-derive it")
        # The round-5 fix's floor inside the gate: every R5F rule names at least one pin, its named control among them.
        self.assertTrue(R5F_RULE_PINS, "R5F_RULE_PINS matched nothing: the round-5 fix pins no rule")
        for rule, (count, site, control) in R5F_RULE_PINS.items():
            named = sorted(k for (k, field), pinned_rule in rules.items() if rule in pinned_rule)
            self.assertTrue(named, f"R5F_RULE_PINS: {rule!r} matched nothing: no vector pins it")
            self.assertIn(control, named, f"R5F_RULE_PINS: {rule!r} is not pinned by its named control {control}")
        self.assertEqual(sorted(f"{k}:{field}" for (k, field), rule in rules.items()
                                if any(rule in part for part in fragments)), [],
                         "a pinned rule the catch-all refusal also prints cannot tell its rule from the catch-all")

    def test_the_action_path_reads_the_scanned_revision(self):
        """action.yml runs `edges.py check --revision <candidate>`: the classifier reads the committed bytes, never a
        later working tree. The round-2 cases whose lines span or shift, plus positive controls that must READ."""
        repo = self.vector_repo("revision")
        for label in self.REVISION_LABELS:
            with self.subTest(label):
                case = self.REVIEW_VECTORS[label]
                self.judge(label, case, self.vector_scan(repo, case, revision=True))
        for label in ("A01_multiline_join_computed", "A02_multiline_join_literal", "N52_formfeed_above_multiline_join"):
            with self.subTest(precision=label):
                self.assertNotEqual(self.vector_scan(repo, self.REVIEW_VECTORS[label], revision=True), "REFUSE")
        # Controls: metadata stays metadata, and a keyword named `parents` is not a parent step.
        self.assertEqual(self.review_scan("{ key: 'services', label: 'Capabilities', icon: Server },", "js"), [])
        self.assertEqual(self.review_scan('(Path(tmp) / "services" / "a" / sub).mkdir(parents=True)', "py"), ["a"])

    def test_round5_precision_narrowings_read_exactly(self):
        """Each round-5 narrowing is a positive-evidence shape, so it must read EXACTLY this, not merely its truth: a
        wide read here means the narrowing was lost (the must-read vectors alone accept an over-read)."""
        for label, want in (("R5R01_py_dot_separator_in_substitution", ["b"]),
                            ("R5R02_yaml_compose_services_key", []),
                            ("R5R03_py_database_execute_not_a_command", []),
                            ("R5R04_py_def_default_cwd_not_a_process_cwd", ["b", "nest"])):
            with self.subTest(label):
                case = self.REVIEW_VECTORS[label]
                self.assertEqual(self.vector_scan(self.vector_repo("exact-" + label[:5]), case), want)

    def test_reader_scan_greps_bytes_whatever_the_callers_locale(self):
        """R7V14: under a UTF-8 locale `git grep -E` stops matching a line at an invalid UTF-8 byte, which hid a root
        mention after it. The scan pins LC_ALL=C; the caller's locale is set to C.UTF-8 here, so a scan that inherited
        it would read nothing."""
        case = self.REVIEW_VECTORS["R7V14_pkg_invalid_utf8_byte_before_script"]
        with patch.dict(os.environ, {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}):
            self.assertEqual(self.vector_scan(self.vector_repo("locale"), case), ["a", "b", "b2", "nest"])

    def test_round7_package_json_and_toml_read_exactly(self):
        """Round 7's reads, pinned exactly (a must-read vector accepts an over-read): a BOM-prefixed package.json reads
        its script; every string script is read, the second included; a non-string or nested value is skipped, and an
        empty or absent `scripts` reads nothing, without refusing; a TOML key reads like any bare word."""
        svc = ["a", "b", "b2", "nest"]
        for label, want in (("R6V15_pkg_utf8_bom", svc),
                            ("R6V16_pkg_two_scripts_second_reads", svc + ["web"]),
                            ("R6V10_pkg_nested_scripts_object", []),
                            ("R6V11_pkg_non_string_values", svc),
                            ("R7T09_pkg_empty_scripts", []),
                            ("R7T10_pkg_bom_no_scripts", []),
                            ("R6V30_toml_key_precision", svc),
                            ("R7T12_toml_colon_key_reads", svc)):
            with self.subTest(label):
                case = self.REVIEW_VECTORS[label]
                self.assertEqual(self.vector_scan(self.vector_repo("exact7-" + label[:6]), case), want)

    def test_an_unowned_path_a_glob_maps_or_inerts_refuses(self):
        """F6: an unowned path is safe to leave unread only because its change is unmapped and plans FULL. When a
        caller's inert_globs or extra_edges covers it, that is no longer true, so the read refuses."""
        sources = (('p = os.path.join(ROOT, "services", "fixtures", "seed.json")', "py"),
                   ('p = "services/fixtures/seed.json"', "py"),  # the literal form, read through a string
                   ("const p = 'services/fixtures/seed.json';", "js"))
        for src, ext in sources:
            self.assertEqual(self.review_scan(src, ext), [])
        for key, value in (("inert_globs", ["services/fixtures/**"]), ("extra_edges", {"services/fixtures/**": ["a"]})):
            for src, ext in sources:
                with self.subTest(key=key, src=src):
                    self.REVIEW_CFG = {**type(self).REVIEW_CFG, key: value}
                    self.assertEqual(self.review_scan(src, ext), "REFUSE")
        self.REVIEW_CFG = type(self).REVIEW_CFG

    def test_reader_scan_uses_immutable_revision_not_later_working_tree(self):
        cfg = self.pnpm_fixture()
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "frozen source"], check=True)
        revision = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        (self.repo / "server/test.ts").write_text("// later working-tree edit removes the reader\n")
        deps, _ = E.scan(self.repo, cfg, revision=revision)
        self.assertEqual(deps["server"], {"cli"})
        self.assertEqual(E.scan(self.repo, cfg)[0]["server"], set())
        with self.assertRaises(ValueError):
            E.scan(self.repo, cfg, revision="main")

    def test_unknown_declared_edge_and_duplicate_pnpm_name_are_not_ignored(self):
        cfg = self.pnpm_fixture()
        cfg["workspace"]["extra_deps"] = {"server": ["missing"]}
        with self.assertRaises(ValueError):
            E.workspace_graph(self.repo, cfg)
        cfg["workspace"].pop("extra_deps")
        (self.repo / "cli/package.json").write_text('{"name":"server"}')
        with self.assertRaises(ValueError):
            E.workspace_graph(self.repo, cfg)


IMPORT_CFG = {
    "schema": 1,
    "workspace": {"type": "declared", "packages": {
        "a": {"dir": "services/a", "deps": []},
        "b": {"dir": "services/b", "deps": []},
        "c": {"dir": "services/c", "deps": []},
        "tp": {"dir": "tools/pkg", "deps": []},
    }},
    "edge_scan": {"roots": ["services"], "reader_dirs": ["scripts", "tools"], "reader_job": "root",
                  "exclude": ["*.md", "docs", ".github", "vendor"]},
    "jobs": {"root": "always"},
}


class ImportAttributionTest(unittest.TestCase):
    """1.5.0: a package is credited with the reads of the files outside every package it imports (cli, 2026-10-27).
    Before it, a relative path resolving outside every package was dropped, so deps(a) missed what scripts/x.mjs read."""

    def setUp(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        isolated = patch.dict(os.environ, environment, clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.repo = Path(self._td.name)
        for d in ("services/a", "services/b", "services/c", "tools/pkg", "scripts", ".github"):
            (self.repo / d).mkdir(parents=True)
        for d in ("services/b", "services/c", "tools/pkg"):
            (self.repo / d / "app.py").write_text("x = 1\n")
        (self.repo / "services/a/app.py").write_text("x = 1\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)

    def files(self, **files):
        for path, text in files.items():
            target = self.repo / path.replace("__", "/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)

    def scan(self, cfg=None):
        report = {}
        deps, readers = E.scan(self.repo, reviewed_cfg(cfg or IMPORT_CFG), report=report)
        return deps, readers, report

    def test_a_package_json_nested_past_the_bound_is_unreadable_in_the_directory_runner_read(self):
        # 1.7.5: basename_mentions parsed a package.json with no bound; RecursionError is no ValueError (3.11-3.13) and
        # CPython 3.14 parses any depth. `files` is publish metadata, skipped when the manifest parses; a manifest past
        # PACKAGE_JSON_MAX_DEPTH is unreadable, so it is read whole and its `../../tools/` mention is a row.
        def manifest(depth):  # the object itself is level 1
            return '{"name":"a","files":["../../tools/"],"x":' + "[" * (depth - 1) + "]" * (depth - 1) + "}\n"
        self.assertEqual(E.json_nesting_depth(manifest(64)), 64)
        self.assertEqual(E.json_nesting_depth(manifest(65)), 65)
        real, seen = json.loads, []

        def loads(text, *args, **kwargs):  # an interpreter that cannot parse past the bound, recording what it is given
            seen.append(E.json_nesting_depth(text))
            if seen[-1] > E.PACKAGE_JSON_MAX_DEPTH:
                raise RecursionError("maximum recursion depth exceeded")
            return real(text, *args, **kwargs)

        def mentions(depth):
            self.files(**{"services__a__package.json": manifest(depth), "tools__run.sh": "echo\n"})
            owner = lambda p: "a" if p.startswith("services/a/") else None
            with patch.object(E.json, "loads", loads):
                return E.basename_mentions(self.repo, {"inert_globs": ["tools/**"]}, owner, None, dict(os.environ), {})
        self.assertEqual(mentions(E.PACKAGE_JSON_MAX_DEPTH), {}, "parsed: the metadata field is skipped")
        self.assertIn(E.PACKAGE_JSON_MAX_DEPTH, seen)
        seen.clear()
        rows = mentions(E.PACKAGE_JSON_MAX_DEPTH + 1)
        self.assertEqual(rows["tools/run.sh"], [["services/a/package.json", "a", False, "tools/"]])
        self.assertEqual(seen, [], "a manifest past the bound never reaches json.loads")

    def test_one_hop_import_credits_the_imported_files_reads(self):
        self.files(**{"services__a__t.test.mjs": 'import { x } from "../../scripts/x.mjs";\n',
                      "scripts__x.mjs": 'export const x = () => readFileSync("services/b/data.json");\n'})
        deps, readers, report = self.scan()
        self.assertEqual(deps["a"], {"b"})
        self.assertEqual(readers["scripts"], {"b"}, "the reader job keeps its credit: nothing is ever narrower")
        self.assertEqual(report["imports"], {"scripts/x.mjs": ["a"]})

    def test_a_dot_slash_import_inside_a_reached_file_is_followed_though_the_grep_never_sees_it(self):
        # y.mjs is reached only through `./y.mjs`, a line with no root and no `../`: only the whole-file read finds it.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n',
                      "scripts__x.mjs": 'import { y } from "./y.mjs";\nexport { y };\n',
                      "scripts__y.mjs": 'export const y = "services/c/z.json";\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"c"})
        self.assertEqual(sorted(report["imports"]), ["scripts/x.mjs", "scripts/y.mjs"])

    def test_cycles_terminate_and_two_importers_are_both_credited(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n',
                      "services__b__t.mjs": 'import "../../scripts/y.mjs";\n',
                      "scripts__x.mjs": 'import "./y.mjs";\nconst p = "services/c/q.json";\n',
                      "scripts__y.mjs": 'import "./x.mjs";\n'})
        deps, _, report = self.scan()
        self.assertEqual((deps["a"], deps["b"]), ({"c"}, {"c"}))
        self.assertEqual(report["imports"], {"scripts/x.mjs": ["a", "b"], "scripts/y.mjs": ["a", "b"]})

    def test_extensionless_require_python_sibling_and_shell_source_resolve(self):
        self.files(**{"services__a__t.cjs": 'const m = require("../../scripts/m");\n',
                      "scripts__m.js": 'module.exports = 1;\nrequire("./run.py");\n',
                      "scripts__run.py": "import helper\n",
                      "scripts__helper.py": 'P = "services/b/x.json"\n',
                      "services__c__t.mjs": 'import "../../scripts/r.sh";\n',
                      "scripts__r.sh": '#!/bin/bash\nsource "$(dirname "$0")/lib.sh"\n',
                      "scripts__lib.sh": "cat services/a/data.txt\n"})
        deps, _, _ = self.scan()
        self.assertEqual(deps["a"], {"b"})
        self.assertEqual(deps["c"], {"a"})

    def test_a_symlinked_file_or_directory_resolves_to_its_target(self):
        self.files(**{"tools__real.mjs": 'export const r = "services/b/x.json";\n',
                      "services__a__t.mjs": 'import "../../scripts/link.mjs";\nimport "../../scripts/dirlink/real.mjs";\n'})
        os.symlink("../tools/real.mjs", self.repo / "scripts/link.mjs")
        os.symlink("../tools", self.repo / "scripts/dirlink")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b"})
        self.assertIn("tools/real.mjs", report["imports"])

    def test_a_directory_target_reads_its_files_and_a_nested_package_is_a_dep(self):
        self.files(**{"services__a__t.mjs": 'const dir = new URL("../../tools/", import.meta.url);\n',
                      "tools__z.mjs": 'export const z = "services/c/z.json";\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"c", "tp"}, "tools/pkg is package tp: an edge to it is a dep, not a closure file")
        self.assertNotIn("tools/pkg/app.py", report["imports"])

    def test_data_targets_are_credited_markdown_is_edge_only_and_a_data_route_is_followed(self):
        # Root's round 3 of #33, B1: a reached data file's ./ route is a route (a compose volume, a tsconfig `files`), so
        # its ./more.mjs is followed and what more.mjs reads (c) is credited too. A .md file stays edge-only.
        self.files(**{"services__a__t.mjs": 'read("../../scripts/data.json"); read("../../scripts/notes.md");\n',
                      "scripts__data.json": '{"dir": "services/b/x", "next": "./more.mjs"}\n',
                      "scripts__more.mjs": 'export const m = "services/c/m.json";\n',
                      "scripts__notes.md": "see services/c\n"})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b", "c"}, "the data file is credited, and so is the module its ./more.mjs names")
        self.assertEqual(sorted(report["imports"]), ["scripts/data.json", "scripts/more.mjs", "scripts/notes.md"])

    def test_fail_closed_on_an_excluded_or_always_only_code_target(self):
        self.files(**{"services__a__t.mjs": 'import "../../vendor/v.mjs";\n', "vendor__v.mjs": "export {};\n"})
        with self.assertRaisesRegex(ValueError, "excludes"):
            self.scan()
        (self.repo / "services/a/t.mjs").write_text('import "../../scripts/s.mjs";\n')
        self.files(**{"scripts__s.mjs": "export {};\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["always_reader_dirs"] = ["scripts"]
        with self.assertRaisesRegex(ValueError, "always_reader_dirs"):
            self.scan(cfg)

    def test_a_refusal_inside_a_reached_file_refuses(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n',
                      "scripts__x.mjs": 'export const p = path.join(ROOT, "services", "..", "b");\n'})
        with self.assertRaises(ValueError):
            self.scan()

    def test_a_shorthand_method_named_require_or_import_is_a_definition_not_a_call(self):
        # Spine (core's console vm sandboxes, 2026-10-27): `{ ..., require(name) { ... } }` defines a method.
        for body in ("vm.runInNewContext(code, { module, require(name) { return stubs[name]; } });\n",
                     "const sandbox = {\n  require(spec) {\n    throw new Error(spec);\n  },\n};\n",
                     "class Box { static require(name) { return name; } import(x) { return x; } }\n"):
            with self.subTest(body=body):
                self.files(**{"services__a__vm.test.mjs": body})
                self.scan()
        # Controls: a real computed call inside that method body stays a site, and ASI keeps `= require(name)` a call.
        controls = {"inner call": "const require_ = createRequire(import.meta.url);\n"
                                  "const s = { require(name) { return require_(name); } };\n",
                    "asi": "const x = require(name)\n{ x(); }\n"}
        for why, body in controls.items():
            with self.subTest(why):
                self.files(**{"services__a__vm.test.mjs": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
                    self.scan()

    def test_a_non_file_url_scheme_import_names_no_file(self):
        for body in ("await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);\n",
                     "await import('data:text/javascript,' + src);\n",
                     "await import(`node:${name}`);\n",
                     "await import(`https://cdn.example/${pkg}`);\n"):
            with self.subTest(body=body):
                self.files(**{"services__a__sync.mjs": body})
                self.scan()
        # Controls: a file: URL and a bare substitution still refuse.
        for body in ("await import(`file:${p}`);\n", "await import(`${p}`);\n"):
            with self.subTest(body=body):
                self.files(**{"services__a__sync.mjs": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()

    def test_computed_imports_refuse_unless_declared_and_an_escape_refuses_even_declared(self):
        self.files(**{"services__a__load.mjs": "export const load = (name) => import(name);\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.mjs", "expr": "name", "reach": "external"}]
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        for escaping in ('import(path.join(here, "..", name))', 'import("../../" + name)', "import(`../../scripts/${n}.mjs`)",
                         'require(join(root, "scripts", n))'):
            with self.subTest(escaping):
                (self.repo / "services/a/load.mjs").write_text(f"export const load = () => {escaping};\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                expr = escaping[escaping.index("(") + 1:-1]
                cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.mjs", "expr": expr, "reach": "external"}]
                # `"../../"` alone resolves to the repository root, which refuses first (D5, N4): either way, never mapped.
                with self.assertRaisesRegex(ValueError, "steps outside its package|the repository root or above it"):
                    self.scan(cfg)

    def test_a_parent_step_inside_the_package_needs_a_package_declaration_and_an_escape_never_passes(self):
        # vagary-core identity's contract-drift test: `import(\`../dist/${m}\`)` stays inside its own package.
        f = "services/a/test/drift.mjs"
        self.files(**{"services__a__test__drift.mjs": "export const d = (m) => import(`../dist/${m}`);\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": "`../dist/${m}`", "reach": "external"}]
        with self.assertRaisesRegex(ValueError, 'must be declared reach "package"'):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"][0]["reach"] = "package"
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        for escaping in ("import(`../../x/${m}`)", "import(`${base}/../x`)", "import(`../dist/${m}/../../../scripts/y.mjs`)",
                         "require(path.resolve(__dirname, '..', '..', 'scripts', x))",
                         "require(path.join(__dirname, x, '..', '..', '..', 'scripts', 'y.mjs'))"):
            with self.subTest(escaping):
                (self.repo / f).write_text(f"export const d = () => {escaping};\n")
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
                cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": escaping[escaping.index("(") + 1:-1],
                                                         "reach": "package"}]
                with self.assertRaisesRegex(ValueError, "steps outside its package"):
                    self.scan(cfg)

    def test_an_all_literal_path_anchored_at_the_file_is_a_literal_import(self):
        # vagary-core webhook-egress's ssrf test: require(path.resolve(__dirname, '..', 'dist', 'ssrf.js')).
        self.files(**{
            "services__a__test__ssrf.test.mjs": "const { v } = require(path.resolve(__dirname, '..', 'dist', 'ssrf.js'));\n"
                                                "const here = dirname(fileURLToPath(import.meta.url));\n"
                                                "const x = await import(pathToFileURL(join(here, '..', '..', '..', "
                                                "'scripts', 'x.mjs')).href);\n",
            "scripts__x.mjs": 'export const x = "services/b/x.json";\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b"}, "the anchored literal chain to scripts/x.mjs is an edge, and its reads credit a")
        self.assertIn("scripts/x.mjs", report["imports"])

    def test_every_module_loader_form_is_held_to_the_declaration_rule(self):
        forms = {"require.resolve": "const p = require.resolve(name);\n",
                 "import.meta.resolve": "const p = import.meta.resolve(name);\n",
                 "createRequire(...)(x)": "const m = createRequire(import.meta.url)(name);\n",
                 "a createRequire binding": "const r = createRequire(import.meta.url);\nconst m = r(name);\n",
                 "module.require": "const m = module.require(name);\n"}
        for why, body in forms.items():
            with self.subTest(why):
                self.files(**{"services__a__load.mjs": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
                    self.scan()
        self.files(**{"services__a__load.mjs": "const m = registry.require(name);\n"})
        self.assertEqual(self.scan()[2]["computed_imports_unused"], [], "control: an object's own `require` is no loader")

    def test_a_literal_under_a_typescript_cast_is_a_literal_and_a_cast_name_is_not(self):
        # vagary-core's services/*/src/observability.ts load `import("@opentelemetry/sdk-node" as string)`: a literal.
        self.files(**{"services__a__obs.ts": 'const m = await import("redis" as string);\n'})
        self.assertEqual(self.scan()[2]["computed_imports_unused"], [])
        (self.repo / "services/a/obs.ts").write_text("const m = await import(name as string);\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name as string`"):
            self.scan()

    def test_a_declared_reach_list_is_an_edge_and_a_stale_declaration_fails_check(self):
        self.files(**{"services__a__load.mjs": "export const load = (f) => import(pathToFileURL(f).href);\n",
                      "scripts__x.mjs": 'export const x = "services/b/x.json";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [
            {"file": "services/a/load.mjs", "expr": "pathToFileURL(f).href", "reach": ["scripts/x.mjs"]},
            {"file": "services/a/gone.mjs", "expr": "x", "reach": "package"}]
        deps, _, report = self.scan(cfg)
        self.assertEqual(deps["a"], {"b"})
        self.assertEqual(report["computed_imports_unused"], ["services/a/gone.mjs: x"])
        assessment = E.assess(E.workspace_graph(self.repo, cfg), cfg, deps, {"scripts": set(), "tools": set()},
                              revision=None, config_path=Path(__file__),
                              computed_unused=report["computed_imports_unused"])
        self.assertIn("stale computed_imports entry: services/a/gone.mjs: x matches no import call", assessment["failures"])

    def test_check_fails_on_an_undeclared_import_edge_until_extra_edges_maps_it(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))

        def check(c):
            (self.repo / ".github/ci-plan.json").write_text(json.dumps(c))
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo)])
            return rc, buf.getvalue()

        rc, out = check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("undeclared import edge: a imports scripts/x.mjs", out)
        cfg["extra_edges"] = {"scripts/x.mjs": ["a"]}
        self.assertEqual(check(cfg)[0], 0)
        import plan
        pkgs = E.workspace_graph(self.repo, cfg)
        selected = plan.classify_paths(["scripts/x.mjs"], cfg, pkgs)
        self.assertEqual((selected["evidence"]["unmapped"], sorted(selected["affected"])), ([], ["a"]),
                         "a change to the imported file selects its importer, not FULL")

    def test_a_name_that_re_enters_the_checkout_by_its_own_name_must_declare_what_it_reaches(self):
        # Root's R4 of #49 (required): CI checks out into .../<repo>/<repo>, so `../<repo>/...` may be this repository's
        # own tree, which a sibling repository's name cannot be told apart from. Reach "none" refuses there, globs too;
        # a reach list is accepted, and a sibling's name with "none" still is.
        entry = lambda name, reach="none": {"file": "services/a/t.mjs", "name": name, "reach": reach, "reason": "fixture",
                                            "review_by": "2026-11-20"}
        own = frozenset({"myrepo"})
        for name in ("../myrepo/scripts/x.mjs", "../../work/myrepo/x.json", "../myrepo/**"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, r"through its own name \(myrepo\)"):
                E.unresolved_name_registry({"unresolved_names": [entry(name)]}, own)
        E.unresolved_name_registry({"unresolved_names": [entry("../myrepo/scripts/x.mjs", ["scripts/x.mjs"])]}, own)
        E.unresolved_name_registry({"unresolved_names": [entry("../vagary-voice/x.json")]}, own)  # a sibling: "none" holds
        # The names: the checkout directory's, and in Actions the repository's (a local clone may be named otherwise).
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "vagarylabs/vagaris"}):
            self.assertEqual(E.own_names(self.repo), {self.repo.resolve().name, "vagaris"})
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_REPOSITORY", None)
            self.assertEqual(E.own_names(self.repo), {self.repo.resolve().name})
        # End to end, by the checkout's own directory name.
        self.files(**{"services__a__t.mjs": 'import { readFileSync } from "node:fs";\n'
                                            f'readFileSync("../../../{self.repo.name}/services/b/app.py");\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["unresolved_names"] = [entry(f"../{self.repo.name}/services/b/app.py")]
        with self.assertRaisesRegex(ValueError, "through its own name"):
            E.scan(self.repo, cfg)

    def test_a_name_above_the_checkout_is_judged_against_the_actual_checkout_path(self):
        # Root's delta R4 of #49 (non-blocking): on CI's .../_work/<repo>/<repo>, `../../../_work/**` is an ANCESTOR of the
        # checkout though it never names the repository, so reach "none" must refuse it. The judgement is lexical, against
        # the checkout path at scan time; the own-name rule still covers a layout that differs between scan and CI.
        ci = "/x/_work/vagaris/vagaris"
        for name, lands in (("../../../_work/**", True), ("../../vagaris", True), ("../vagaris/x.json", True),
                            ("../../../_work/cache/x.json", False), ("../../other/x", False), ("../sibling", False),
                            ("../../../_workspace/x", False), ("../../../_wo", False), ("../vagaris2/x", False)):
            with self.subTest(name=name):
                self.assertEqual(E.lands_on_checkout(name, ci), lands)
        self.assertFalse(E.lands_on_checkout("../..", None), "no checkout path, no judgement")
        entry = lambda name, reach="none": {"file": "scripts/run-all.mjs", "name": name, "reach": reach, "reason": "fixture",
                                            "review_by": "2026-11-20"}
        with self.assertRaisesRegex(ValueError, "resolves from this checkout to the checkout itself, inside it, or an ancestor"):
            E.unresolved_name_registry({"unresolved_names": [entry("../../../_work/**")]}, frozenset({"vagaris"}), ci)
        E.unresolved_name_registry({"unresolved_names": [entry("../../../_work/**")]}, frozenset({"vagaris"}),
                                   "/home/me/src/vagaris")  # the same name is no ancestor of a local checkout
        E.unresolved_name_registry({"unresolved_names": [entry("../../../_work/**", ["scripts/x.mjs"])]},
                                   frozenset({"vagaris"}), ci)  # a reach list is accepted
        # End to end: a literal ancestor of THIS checkout, named without `..` steps alone or the checkout's own name.
        parent = self.repo.resolve().parent
        name = f"../../{parent.name}/**"
        self.assertTrue(E.lands_on_checkout(name, self.repo.resolve().as_posix()))
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["unresolved_names"] = [entry(name)]
        with self.assertRaisesRegex(ValueError, "an ancestor of it"):
            E.scan(self.repo, cfg)

    def test_every_git_grep_of_the_scan_refuses_typed_when_it_cannot_read(self):
        # Root's carry-over from #47 (556963a): no grep site of the scan may fail by a bare SystemExit. Each `git grep` the
        # scan runs on this tree is made to exit 128 in turn (git 2.56's unreadable-blob status); every one refuses typed,
        # and the labels cover 1.5.2's own sites: the shell and Python listings and the Python import grep.
        self.files(**{
            "services__a__test__conftest.py": "import os, sys\n"
                                              'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts"))\n',
            "services__a__test__test_x.py": "import helper\n",
            "scripts__helper.py": 'P = "services/b/x.json"\n',
            "scripts__run.sh": "echo checking\n",  # the shell listing reads every *.sh, whatever it holds
            "services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        head = self._commit(self.repo, "head")
        cfg = reviewed_cfg({**IMPORT_CFG, "extra_edges": {"scripts/x.mjs": ["a"]}})
        real = subprocess.run
        greps = []

        def counting(argv, *args, **kwargs):
            if "grep" in argv[:6]:
                greps.append(argv)
            return real(argv, *args, **kwargs)

        with patch.object(E.subprocess, "run", counting):
            E.scan(self.repo, cfg, revision=head)  # control: every grep reads, and the scan completes
        self.assertGreaterEqual(len(greps), 5)
        labels = set()
        for k in range(len(greps)):
            seen = []

            def failing(argv, *args, **kwargs):
                if "grep" in argv[:6]:
                    seen.append(argv)
                    if len(seen) == k + 1:
                        return subprocess.CompletedProcess(argv, 128, b"", b"fatal: planted\n")
                return real(argv, *args, **kwargs)

            with patch.object(E.subprocess, "run", failing), self.assertRaises(ValueError, msg=f"grep #{k}") as caught:
                E.scan(self.repo, cfg, revision=head)
            message = str(caught.exception)
            self.assertIn("(git grep exit 128: fatal: planted)", message, f"grep #{k}")
            labels.add(re.search(r"reader closure unproven: (.*?) could not read the scanned tree", message).group(1))
        self.assertLessEqual({"the reader scan's shell listing", "the reader scan's Python listing",
                              "the reader scan's Python import grep", "the reader scan"}, labels)

    def test_python_sys_path_entries_credit_what_the_package_imports_by_name(self):
        # 1.5.2. The entry sits in conftest.py, and the import in another test file: sys.path is process-wide.
        self.files(**{
            "services__a__test__conftest.py": "import os, sys\n"
                                              'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts"))\n',
            "services__a__test__test_x.py": "import helper\n",
            "scripts__helper.py": 'P = "services/b/x.json"\n',
            "scripts__unused.py": 'Q = "services/c/q.json"\n'})
        deps, _, report = self.scan()
        self.assertEqual(deps["a"], {"b"}, "only a module the package imports by name is credited")
        self.assertIn("scripts/helper.py", report["imports"])
        self.assertNotIn("scripts/unused.py", report["imports"])

    def test_a_sys_path_entry_into_another_package_is_a_dep_and_into_its_own_is_nothing(self):
        self.files(**{"services__a__t.py": "import sys\nfrom pathlib import Path\n"
                                            'APP = Path(__file__).resolve().parent / "app"\n'
                                            'OTHER = Path(__file__).resolve().parents[1] / "b" / "app"\n'
                                            "sys.path.insert(0, str(APP))\nsys.path.insert(0, str(OTHER))\n"})
        self.assertEqual(self.scan()[0]["a"], {"b"})

    def test_an_unresolved_sys_path_entry_refuses_when_it_may_leave_its_package(self):
        for entry in ('os.environ.get("X", "../scripts")', 'os.path.join(ROOT, "scripts")', 'os.path.join(REPO, "services", "b")'):
            with self.subTest(entry):
                self.files(**{"services__a__t.py": f"import os, sys\nsys.path.insert(0, {entry})\n"})
                with self.assertRaisesRegex(ValueError, "sys.path entry"):
                    self.scan()
        self.files(**{"services__a__t.py": "import os, sys\nsys.path.insert(0, os.getcwd())\n"})
        self.assertEqual(self.scan()[0]["a"], set(), "control: no parent step, no top-level name: a documented residual")

    def test_every_sys_path_form_and_an_unparseable_file(self):
        entry = 'os.path.join(os.path.dirname(__file__), "..", "..", "scripts")'
        for form in ("sys.path.append(E)", "sys.path.extend([E])", "sys.path += [E]", "sys.path[0:0] = [E]"):
            with self.subTest(form):
                self.files(**{"services__a__t.py": f"import os, sys\n{form.replace('E', entry)}\nimport helper\n",
                              "scripts__helper.py": 'P = "services/b/x.json"\n'})
                self.assertEqual(self.scan()[0]["a"], {"b"})
        self.files(**{"services__a__t.py": "import sys\nsys.path.insert(0, 'x'\n"})
        with self.assertRaisesRegex(ValueError, "does not parse"):
            self.scan()

    def test_pytest_pythonpath_is_a_sys_path_entry_from_the_config_pytest_would_pick(self):
        # Root-level configs with no `../` in them, so only rule 6 can see the entry (a package file's `../` path is a
        # rule-1 edge on its own). A root pyproject.toml puts scripts/ on every package's path.
        self.files(**{"pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["scripts"]\n',
                      "services__a__test_x.py": "import helper\n",
                      "scripts__helper.py": 'P = "services/b/x.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})
        # In one directory pytest.ini wins over pyproject.toml, even with no [pytest] section.
        self.files(**{"pytest.ini": "# empty: still the config\n"})
        self.assertEqual(self.scan()[0]["a"], set())
        # An entry into package c is a dep of every other Python package the config serves.
        (self.repo / "pytest.ini").unlink()
        self.files(**{"pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["services/c/app"]\n'})
        deps = self.scan()[0]
        self.assertEqual((deps["a"], deps["b"], deps["c"]), ({"c"}, {"c"}, set()))
        # The NEAREST config wins: a's own pytest.ini (an entry inside a) shadows the root's entry into c for a only.
        self.files(**{"services__a__pytest.ini": "[pytest]\npythonpath = sub\n"})
        deps = self.scan()[0]
        self.assertEqual((deps["a"], deps["b"]), (set(), {"c"}))
        (self.repo / "services/a/pytest.ini").unlink()
        # The package's own unreadable setup.cfg is the one pytest would read, so it refuses.
        self.files(**{"services__a__setup.cfg": "[tool:pytest\npythonpath = x\n"})
        with self.assertRaisesRegex(ValueError, "does not parse"):
            self.scan()

    def test_python_loaders_by_computed_name_or_path_are_held_to_the_declaration_rule(self):
        self.files(**{"services__a__load.py": "import importlib\nm = importlib.import_module(name)\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.py", "expr": "name", "reach": "external"}]
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        for why, body in (("__import__", "m = __import__(name)\n"), ("runpy.run_module", "import runpy\nrunpy.run_module(name)\n"),
                          ("exec(open(p).read())", "exec(open(p).read())\n")):
            with self.subTest(why):
                self.files(**{"services__a__load.py": body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()
        # A path from __file__ with literal parts is a literal load: an edge, credited, with no declaration.
        self.files(**{"services__a__load.py": "import os, importlib.util\nspec = importlib.util.spec_from_file_location("
                                               '"m", os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "m.py"))\n',
                      "scripts__m.py": 'P = "services/b/m.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})
        # An unevaluated path naming a parent step or an outside top-level directory refuses even when declared.
        for escaping in ('runpy.run_path(os.path.join(ROOT, "scripts", "x.py"))', 'runpy.run_path("../../x.py")'):
            with self.subTest(escaping):
                self.files(**{"services__a__load.py": f"import os, runpy\n{escaping}\n"})
                cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.py",
                                                         "expr": escaping[escaping.index("(") + 1:-1], "reach": "package"}]
                with self.assertRaisesRegex(ValueError, "may leave its package"):
                    self.scan(cfg)

    def test_python_loaders_get_fix_1_and_fix_2_shape(self):
        # Root's R4 of #33 carried into 1.5.2's Python loaders: an unowned file's loaders are checked and select its
        # own unit, a literal load naming no tracked file refuses, and reach "package" refuses outside every package.
        self.files(**{"scripts__x.py": "import importlib\nm = importlib.import_module(name)\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()
        self.files(**{"scripts__x.py": "import os, importlib.util\nspec = importlib.util.spec_from_file_location("
                                       '"m", os.path.join(os.path.dirname(__file__), "..", "services", "b", "m.py"))\n',
                      "services__b__m.py": "M = 1\n",
                      "services__a__run.sh": "#!/bin/bash\npython3 ../../scripts/x.py\n"})
        deps, readers, report = self.scan()
        self.assertEqual(readers["scripts"], {"b"}, "x.py's own unit, the scripts/ reader job, loads b")
        self.assertEqual(deps["a"], {"b"}, "a runs x.py, so a is credited with what it loads")
        self.assertEqual(report["unowned_callers"], {"scripts/x.py": {"unit": "scripts", "reaches": ["b"]}})
        self.files(**{"services__a__load.py": "import os, runpy\nrunpy.run_path(os.path.join(os.path.dirname(__file__), "
                                               '"..", "..", "scripts", "gone.py"))\n'})
        with self.assertRaisesRegex(ValueError, "a reaches scripts/gone.py, which names no tracked file"):
            self.scan()
        (self.repo / "services/a/load.py").unlink()
        self.files(**{"scripts__x.py": "import importlib\nm = importlib.import_module(name)\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "scripts/x.py", "expr": "name", "reach": "package"}]
        with self.assertRaisesRegex(ValueError, 'declared reach "package", but scripts/x.py is outside every package'):
            self.scan(cfg)

    def test_an_unowned_caller_loading_an_unowned_path_declares_it_and_a_parent_step_still_escapes(self):
        # Spine's A2 census (2026-10-28): scripts/identity-products-apply.py's `HERE / file` and
        # scripts/test_contract_drift.py's `_mod.ROOT / "scripts/gen-capability-docs.py"`. The caller is outside every
        # package, so the load leaves no package: it is a load to declare (reach as paths), not an escape.
        cases = {"evaluated prefix": 'from pathlib import Path\nimport runpy\nHERE = Path(__file__).parent\n'
                                     'runpy.run_path(str(HERE / file))\n',
                 "unevaluated prefix": 'import runpy\nrunpy.run_path(str(_mod.ROOT / "scripts/gen.py"))\n'}
        for why, body in cases.items():
            with self.subTest(why):
                self.files(**{"scripts__apply.py": body, "scripts__gen.py": "G = 1\n"})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()
                expr = "str(HERE / file)" if why == "evaluated prefix" else 'str(_mod.ROOT / "scripts/gen.py")'
                cfg = json.loads(json.dumps(IMPORT_CFG))
                cfg["edge_scan"]["computed_imports"] = [{"file": "scripts/apply.py", "expr": expr, "reach": ["scripts/gen.py"]}]
                self.scan(cfg)
                (self.repo / "scripts/apply.py").unlink()
        # Controls: an unowned caller whose prefix has a package beneath it (the repo root via `..`, or services/) still
        # escapes, and package code reaching an unowned path still escapes, declared or not.
        for body in ('from pathlib import Path\nimport runpy\nHERE = Path(__file__).parent\nrunpy.run_path(str(HERE / ".." / file))\n',
                     'from pathlib import Path\nimport runpy\nROOT = Path(__file__).parents[1]\nrunpy.run_path(str(ROOT / "services" / name))\n'):
            with self.subTest(body=body):
                self.files(**{"scripts__apply.py": body})
                with self.assertRaisesRegex(ValueError, "may leave its package"):
                    self.scan()
                (self.repo / "scripts/apply.py").unlink()
        self.files(**{"services__a__load.py": 'import runpy\nrunpy.run_path(str(_mod.ROOT / "scripts/gen.py"))\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.py", "expr": 'str(_mod.ROOT / "scripts/gen.py")',
                                                 "reach": ["scripts/gen.py"]}]
        with self.assertRaisesRegex(ValueError, "may leave its package"):
            self.scan(cfg)

    def test_pathlib_edits_evaluate_and_the_floor_judges_the_evaluated_prefix(self):
        # vagary-core's evidence app vendors a package INSIDE itself: PACKAGE / "scripts/..." is its own subdirectory,
        # not the top-level scripts/ (spine, 2026-10-27; a rewrite to the repo-root copy would have broken the service).
        self.files(**{"services__a__app__contract.py": "import importlib.util\nfrom pathlib import Path\n"
                                                        'PACKAGE = Path(__file__).with_name("_vendored")\n'
                                                        'spec = importlib.util.spec_from_file_location("m", PACKAGE / "scripts/x.py")\n',
                      "services__a__app___vendored__scripts__x.py": 'P = "services/b/x.json"\n'})
        deps, _, report = self.scan()
        self.assertEqual(report["computed_imports_unused"], [])
        self.assertNotIn("services/a/app/_vendored/scripts/x.py", report["imports"], "inside the importing package: no edge")
        # The same shape with a prefix that does not evaluate still refuses: nothing says where "scripts" is.
        self.files(**{"services__a__app__contract.py": "import importlib.util\n"
                                                        'spec = importlib.util.spec_from_file_location("m", PKG / "scripts/x.py")\n'})
        with self.assertRaisesRegex(ValueError, "may leave its package"):
            self.scan()
        # An evaluated prefix OUTSIDE the package (the repo root's scripts/) with a computed tail refuses, even declared.
        cfg = json.loads(json.dumps(IMPORT_CFG))
        root_tail = 'ROOT / "scripts" / x'
        self.files(**{"services__a__app__contract.py": "import runpy\nfrom pathlib import Path\n"
                                                        "ROOT = Path(__file__).resolve().parents[3]\n"
                                                        f"runpy.run_path({root_tail})\n"})
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/app/contract.py", "expr": root_tail, "reach": "package"}]
        with self.assertRaisesRegex(ValueError, "may leave its package"):
            self.scan(cfg)
        # An evaluated in-package prefix with a computed tail is declarable, as reach "package" only.
        inside_tail = 'PACKAGE / "scripts" / x'
        self.files(**{"services__a__app__contract.py": "import runpy\nfrom pathlib import Path\n"
                                                        'PACKAGE = Path(__file__).with_name("_vendored")\n'
                                                        f"runpy.run_path({inside_tail})\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan()
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/app/contract.py", "expr": inside_tail, "reach": "external"}]
        with self.assertRaisesRegex(ValueError, 'must be declared reach "package"'):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"][0]["reach"] = "package"
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])
        # An evaluated prefix inside ANOTHER package with a computed tail is declarable, and a dep on that package.
        other_tail = 'PLANE / (name + ".py")'
        self.files(**{"services__a__app__contract.py": "import runpy\nfrom pathlib import Path\n"
                                                        'PLANE = Path(__file__).resolve().parents[2] / "c" / "app"\n'
                                                        f"runpy.run_path({other_tail})\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan()
        cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/app/contract.py", "expr": other_tail, "reach": "external"}]
        self.assertIn("c", self.scan(cfg)[0]["a"], "the prefix's package c is a dep (only the vendored file reads b)")
        # joinpath evaluates too: a sys.path entry into package b through it is a dep.
        self.files(**{"services__a__app__contract.py": "import sys\nfrom pathlib import Path\n"
                                                        'sys.path.insert(0, str(Path(__file__).resolve().parents[2].joinpath("b", "app")))\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})

    def test_a_loop_over_a_literal_is_literal_names_and_anything_short_of_it_refuses(self):
        # vagary-core's observability.py: `for mod_name, cls in ((<const>, <const>), ...): import_module(mod_name)`.
        loads = {
            "a literal tuple of pairs": 'for mod_name, cls in (("redis", "R"), ("dns", "D")):\n    m = importlib.import_module(mod_name)\n',
            "a module-level name bound once": 'MODS = ("redis", "dns")\nfor m in MODS:\n    importlib.import_module(m)\n',
            "a comprehension": 'mods = [importlib.import_module(m) for m in ("redis",)]\n',
        }
        for why, body in loads.items():
            with self.subTest(why):
                self.files(**{"services__a__load.py": "import importlib\n" + body})
                self.assertEqual(self.scan()[2]["computed_imports_unused"], [], "no declaration needed")
        refused = {
            "the literal mutated after binding": 'MODS = ["redis"]\nMODS.append(x)\nfor m in MODS:\n    importlib.import_module(m)\n',
            "the loop variable rebound in the body": 'for m in ("redis",):\n    m = other\n    importlib.import_module(m)\n',
            "an f-string argument": 'for m in ("redis",):\n    importlib.import_module(f"x.{m}")\n',
            "an iterable from a call": 'for m in sorted(("redis",)):\n    importlib.import_module(m)\n',
            "a name bound twice": 'MODS = ("a",)\nMODS = ("b",)\nfor m in MODS:\n    importlib.import_module(m)\n',
        }
        for why, body in refused.items():
            with self.subTest(why):
                self.files(**{"services__a__load.py": "import importlib\n" + body})
                with self.assertRaisesRegex(ValueError, "undeclared computed import"):
                    self.scan()
        # The names resolve by name like any import: through a sys.path entry they are edges, and credited.
        self.files(**{"services__a__load.py": "import importlib, os, sys\n"
                                               'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))\n'
                                               'for m in ("helper",):\n    importlib.import_module(m)\n',
                      "scripts__helper.py": 'P = "services/b/x.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})

    def test_a_literal_loader_name_resolves_through_a_sys_path_entry(self):
        self.files(**{"services__a__t.py": "import os, sys\n"
                                            'sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))\n'
                                            'mod = __import__("helper")\n',
                      "scripts__helper.py": 'P = "services/b/x.json"\n'})
        self.assertEqual(self.scan()[0]["a"], {"b"})
        # A reached Python file's own computed loader is held to the same rule.
        self.files(**{"scripts__helper.py": 'import importlib\nP = "services/b/x.json"\nm = importlib.import_module(name)\n'})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`.* in scripts/helper.py"):
            self.scan()
    def check(self, cfg):
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(reviewed_cfg(cfg)))
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo)])
        return rc, buf.getvalue()

    def test_root_r4_counterexample_a_js_specifier_of_a_ts_file_is_never_dropped(self):
        # root's R4 of #33 (2026-10-27): c imported scripts/x.ts as ../../scripts/x.js and was DROPPED, so the mapping
        # check requested ({"scripts/x.ts": ["a"]}) passed and a change to x.ts selected only a, narrower than FULL.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.ts";\n',
                      "services__c__t.mjs": 'import { x } from "../../scripts/x.js";\n',
                      "scripts__x.ts": "export const x = 1;\n"})
        self.assertEqual(self.scan()[2]["imports"], {"scripts/x.ts": ["a", "c"]})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["extra_edges"] = {"scripts/x.ts": ["a"]}
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1, "the narrowing mapping no longer passes")
        self.assertIn("undeclared import edge: c imports scripts/x.ts", out)
        cfg["extra_edges"] = {"scripts/x.ts": ["a", "c"]}
        self.assertEqual(self.check(cfg)[0], 0)
        import plan
        selected = plan.classify_paths(["scripts/x.ts"], cfg, E.workspace_graph(self.repo, cfg))
        self.assertEqual(sorted(selected["affected"]), ["a", "c"])

    def test_every_typescript_source_form_resolves(self):
        cases = {"x.jsx": "scripts/x.tsx", "x.mjs": "scripts/x.mts", "x.cjs": "scripts/x.cts", "y.js": "scripts/y.d.ts"}
        for spec, source in cases.items():
            with self.subTest(spec):
                self.files(**{"services__a__t.mjs": f'import "../../scripts/{spec}";\n',
                              source.replace("/", "__"): "export {};\n"})
                self.assertIn(source, self.scan()[2]["imports"])

    def test_a_path_that_names_nothing_refuses_and_an_untracked_path_in_a_package_maps_to_it(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/gone.js";\n'})
        with self.assertRaisesRegex(ValueError, "services/a/t.mjs names scripts/gone.js, which is no tracked file or directory"):
            self.scan()
        # A build output in a package (untracked dist/) stands for that package: a dep, never dropped. tools/run.mjs
        # names it as ./pkg/dist/index.js, a line with no root and no ../, so only the whole-file read sees it.
        self.files(**{"services__a__t.mjs": 'import "../../tools/run.mjs";\n',
                      "tools__run.mjs": 'export { p } from "./pkg/dist/index.js";\n'})
        self.assertEqual(self.scan()[0]["a"], {"tp"})

    def test_spine_control_an_unowned_caller_selects_its_own_unit_and_credits_its_importers(self):
        # spine's binding control for fix 2 (2026-10-27): a root-level scripts/x.mjs loads services/b/src/y.ts through
        # a declared computed import. Touching y must select x's unit (the reader job), and a package that imports x
        # is credited with b. Before fix 2 an unowned caller's computed import credited nothing.
        decl = [{"file": "scripts/x.mjs", "expr": "pathToFileURL(f).href", "reach": ["services/b/src/y.ts"]}]
        self.files(**{"scripts__x.mjs": "export const load = (f) => import(pathToFileURL(f).href);\n",
                      "services__b__src__y.ts": "export const y = 1;\n",
                      "services__a__t.mjs": 'import { load } from "../../scripts/x.mjs";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = decl
        cfg["jobs"] = {"root": {"packages": []}}
        deps, readers, report = self.scan(cfg)
        self.assertEqual(readers["scripts"], {"b"}, "x's own unit, the scripts/ reader job, reads b")
        self.assertEqual(deps["a"], {"b"}, "a reaches x, so a is credited with what x loads")
        self.assertEqual(report["unowned_callers"], {"scripts/x.mjs": {"unit": "scripts", "reaches": ["b"]}})
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("scripts/ reads b, but job 'root' does not list it", out)
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        cfg["workspace"]["packages"]["a"]["deps"] = ["b"]
        # scripts/x.mjs sits in the reader directory scripts/, so a change to it must still run that job (D5, N3): the
        # mapping names b, which the root job lists, beside its importer a.
        cfg["extra_edges"] = {"scripts/x.mjs": ["a", "b"]}
        self.assertEqual(self.check(cfg)[0], 0)
        import plan
        affected = plan.classify_paths(["services/b/src/y.ts"], cfg, E.workspace_graph(self.repo, cfg))["affected"]
        self.assertEqual(plan.rule_matches(cfg["jobs"]["root"], affected)[0], True, "touching y selects x's unit")

    def test_an_unowned_caller_outside_every_reader_dir_maps_to_unmapped_and_plans_full(self):
        self.files(**{"x.mjs": "export const load = (f) => import(pathToFileURL(f).href);\n",
                      "services__b__src__y.ts": "export const y = 1;\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "x.mjs", "expr": "pathToFileURL(f).href",
                                                 "reach": ["services/b/src/y.ts"]}]
        _, readers, report = self.scan(cfg)
        self.assertEqual(readers["<unmapped>"], {"b"})
        self.assertEqual(report["unowned_callers"], {"x.mjs": {"unit": "<unmapped>", "reaches": ["b"]}})
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1, "no unit runs x.mjs, so check fails and the plan is FULL, never a drop")
        self.assertIn("unmapped source readers require a declared obligation: b", out)

    def test_an_unowned_files_undeclared_computed_import_refuses(self):
        self.files(**{"scripts__x.mjs": "export const load = (name) => import(name);\n"})
        with self.assertRaisesRegex(ValueError, "undeclared computed import `name`"):
            self.scan()

    def test_reach_package_outside_every_package_refuses(self):
        # Root's R4 of #33, fix 4: reach "package" for a file outside every package names and credits nothing.
        self.files(**{"scripts__x.mjs": "export const load = (name) => import(name);\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["computed_imports"] = [{"file": "scripts/x.mjs", "expr": "name", "reach": "package"}]
        with self.assertRaisesRegex(ValueError, 'declared reach "package", but scripts/x.mjs is outside every package'):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"][0]["reach"] = "external"
        self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [], "control: another reach is accepted")

    def test_root_r4_an_escape_can_never_be_declared_away(self):
        # Root's R4 of #33, fix 3: a parent step after the join's closing bracket, and nested dirname() calls, escape.
        f = "services/a/load.mjs"
        cfg = json.loads(json.dumps(IMPORT_CFG))
        for escaping in ('import(path.join(__dirname, "lib") + "/../../../scripts/x.mjs")',
                         'import(path.join(dirname(dirname(__dirname)), "x", n))',
                         'import(join(path.dirname(here), "lib", n))'):
            for reach in ("package", "external"):
                with self.subTest(escaping, reach=reach):
                    self.files(**{"services__a__load.mjs": f"export const load = (n, here) => {escaping};\n"})
                    cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": escaping[escaping.index("(") + 1:-1],
                                                             "reach": reach}]
                    with self.assertRaisesRegex(ValueError, "steps outside its package|the repository root or above it"):
                        self.scan(cfg)
        # Controls: the file's own directory is the anchor, not a step up, and a literal tail without `..` is no escape.
        for fine in ('import(path.join(dirname(fileURLToPath(import.meta.url)), "lib", n))',
                     'import(path.join(path.dirname(__filename), "lib", n))',
                     'import(path.join(__dirname, "lib") + ".mjs")'):
            with self.subTest(fine):
                self.files(**{"services__a__load.mjs": f"export const load = (n) => {fine};\n"})
                cfg["edge_scan"]["computed_imports"] = [{"file": f, "expr": fine[fine.index("(") + 1:-1],
                                                         "reach": "external"}]
                self.assertEqual(self.scan(cfg)[2]["computed_imports_unused"], [])

    def test_an_anchored_literal_join_followed_by_a_computed_tail_is_no_literal_import(self):
        # Kills root's m3 (`if not rest:`): the chain closes, then `+ name` is computed, so it must be declared.
        self.files(**{"services__a__load.mjs": 'export const load = (name) => import(path.join(__dirname, "lib") + name);\n'})
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan()

    def test_check_fails_on_an_imported_path_that_inert_globs_hides(self):
        # The end-to-end selection census (2026-10-27): vagaris's candidate config makes docs/** inert, and the server
        # imports docs/docs.json, so a change to it selected NOTHING though check had asked for extra_edges.
        self.files(**{"services__a__t.mjs": 'import data from "../../scripts/data/x.json";\n',
                      "scripts__data__x.json": "{}\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["extra_edges"] = {"scripts/data/x.json": ["a"]}
        cfg["inert_globs"] = ["scripts/data/**"]
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("inert import: scripts/data/x.json is imported by a, but inert_globs 'scripts/data/**'", out)
        import plan
        self.assertEqual(plan.classify_paths(["scripts/data/x.json"], cfg, E.workspace_graph(self.repo, cfg))["affected"],
                         set(), "the hole itself: inert wins over extra_edges")
        cfg["inert_globs"] = ["scripts/data/*.md"]
        self.assertEqual(self.check(cfg)[0], 0, "control: a glob that leaves the import out is accepted")

    def test_a_trailing_slash_exclude_names_its_directory(self):
        # Root's R4 of #33 (non-blocking): `vendor/` never matched in excluded(), though git's pathspec excludes it.
        self.files(**{"services__a__t.mjs": 'import "../../third/x.mjs";\n', "third__x.mjs": "export {};\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["exclude"] = ["*.md", "docs", ".github", "third/"]
        with self.assertRaisesRegex(ValueError, "a reaches third/x.mjs, code the scan excludes"):
            self.scan(cfg)

    def test_d5_every_route_that_resolves_to_nothing_refuses_in_any_position(self):
        # Root's delta R4 of #33, D5 (N1): a scan that cannot run a line cannot tell a module position from data, so a
        # name that resolves to no tracked file refuses wherever it stands: every spelling below plans [a] at 7b83bf159e
        # although the file it loads is a's dependency. node_modules stays external.
        spellings = {
            "timeout": "timeout 300 node ../../tools/dist/x.js\n",
            "npx tsx": "npx tsx ../../tools/dist/x.js\n",
            "env -i": "env -i node ../../tools/dist/x.js\n",
            "node --import": "node --import ../../tools/dist/x.js main.js\n",
            "pnpm exec": "pnpm exec node ../../tools/dist/x.js\n",
            "xargs": "printf a | xargs node ../../tools/dist/x.js\n",
            "nohup": "nohup node ../../tools/dist/x.js &\n",
            "heredoc import": "node --input-type=module <<'EOF'\nimport \"../../tools/dist/x.js\";\nEOF\n",
            "find pattern": "find . ! -path '../../tools/dist/x.js'\n",
        }
        for why, body in spellings.items():
            with self.subTest(why):
                self.files(**{"services__a__run.sh": "#!/bin/bash\n" + body})
                with self.assertRaisesRegex(ValueError, "names tools/dist/x.js, which is no tracked file or directory"):
                    self.scan()
        for why, js in {"fork": 'fork("../../tools/dist/x.js");', "Worker": 'new Worker("../../tools/dist/x.js");',
                        "spawn": 'spawn(process.execPath, ["../../tools/dist/x.js"]);'}.items():
            with self.subTest(why):
                self.files(**{"services__a__run.sh": "#!/bin/bash\n", "services__a__w.mjs": js + "\n"})
                with self.assertRaisesRegex(ValueError, "names tools/dist/x.js, which is no tracked file or directory"):
                    self.scan()
        with self.subTest("package.json script"):
            self.files(**{"services__a__w.mjs": "export {};\n",
                          "services__a__package.json": '{"scripts": {"t": "node ../../tools/dist/x.js"}}\n'})
            with self.assertRaisesRegex(ValueError, "names tools/dist/x.js, which is no tracked file or directory"):
                self.scan()
        self.files(**{"services__a__package.json": '{"scripts": {"t": "node ../../node_modules/.bin/vitest"}}\n'})
        self.scan()  # an installed binary is external

    def test_d5_a_declared_unresolved_name_names_nothing_or_stands_for_its_paths(self):
        self.files(**{"services__a__run.sh": "#!/bin/bash\nnode ../../tools/dist/x.js\ncat ../../tools/out/r.txt\n",
                      "tools__x.ts": 'export const p = "services/b/p.json";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        # Root's round 3 of #33, F09: reach "none" for a CODE name says it runs nothing, so it refuses.
        cfg["edge_scan"]["unresolved_names"] = [{"file": "services/a/run.sh", "name": "tools/dist/x.js", "reach": "none"},
                                                {"file": "services/a/run.sh", "name": "tools/out/r.txt", "reach": "none"}]
        with self.assertRaisesRegex(ValueError, r"names tools/dist/x.js, a code file, with reach \"none\""):
            self.scan(cfg)
        cfg["edge_scan"]["unresolved_names"][0]["reach"] = ["tools/x.ts"]
        deps, _, report = self.scan(cfg)
        self.assertEqual(report["unresolved_data_names"], ["tools/dist/x.js", "tools/out/r.txt"],
                         "both names resolve to nothing; the data one may reach nothing, the code one reaches its source")
        deps, _, report = self.scan(cfg)
        self.assertEqual(deps["a"], {"b"}, "a build output declared as its source is an edge to that source")
        self.assertEqual(report["imports"]["tools/x.ts"], ["a"])
        cfg["edge_scan"]["unresolved_names"][0]["reach"] = ["tools/also-gone.ts"]  # a declared reach that names nothing
        with self.assertRaisesRegex(ValueError, "reaches tools/also-gone.ts, which names no tracked file or directory"):
            self.scan(cfg)
        cfg["edge_scan"]["unresolved_names"][0]["reach"] = ["tools/x.ts"]
        cfg["edge_scan"]["unresolved_names"].append({"file": "services/a/run.sh", "name": "tools/gone.txt", "reach": "none"})
        self.assertIn("unresolved_names services/a/run.sh: tools/gone.txt", self.scan(cfg)[2]["computed_imports_unused"])
        cfg["edge_scan"]["unresolved_names"] = [{"file": "services/a/run.sh", "name": "tools/dist/x.js", "reach": "some"}]
        with self.assertRaisesRegex(ValueError, "unresolved_names entries must be"):
            self.scan(cfg)

    def test_the_declaration_lists_are_a_reviewed_registry_that_fails_toward_full(self):
        # Root's ruling on #33 round 3: a reason, and a review_by within 30 days of today(); otherwise the scan refuses.
        self.files(**{"services__a__run.sh": "#!/bin/bash\ncat ../../tools/out/r.txt\n",
                      "services__a__load.mjs": "export const l = (name) => import(name);\n"})
        names = {"file": "services/a/run.sh", "name": "tools/out/r.txt", "reach": "none"}
        loads = {"file": "services/a/load.mjs", "expr": "name", "reach": "external"}
        good = {"reason": "a report the test writes, never run", "review_by": "2026-11-28"}
        for kind, entry in (("unresolved_names", names), ("computed_imports", loads)):
            other = ("computed_imports", loads) if kind == "unresolved_names" else ("unresolved_names", names)
            for why, review, message in (
                    ("no reason", {"reason": " ", "review_by": "2026-11-20"}, "has no reason"),
                    ("expired", {"reason": "r", "review_by": "2026-10-28"}, "expired on 2026-10-28"),
                    ("too far", {"reason": "r", "review_by": "2026-11-29"}, "more than 30 days out"),
                    ("not a date", {"reason": "r", "review_by": "soon"}, "is not an ISO date")):
                with self.subTest(kind=kind, why=why):
                    cfg = json.loads(json.dumps(IMPORT_CFG))
                    cfg["edge_scan"][kind] = [{**entry, **review}]
                    cfg["edge_scan"][other[0]] = [{**other[1], **good}]
                    with self.assertRaisesRegex(ValueError, rf"edge_scan.{kind} registry review: .*{message}"):
                        E.scan(self.repo, cfg)
            cfg = json.loads(json.dumps(IMPORT_CFG))
            cfg["edge_scan"]["unresolved_names"] = [{**names, **good}]
            cfg["edge_scan"]["computed_imports"] = [{**loads, **good}]
            E.scan(self.repo, cfg)  # control: both reviewed, the last day of the window included
            cfg["edge_scan"][kind] = [entry]
            with self.assertRaisesRegex(ValueError, rf"edge_scan.{kind} entries must be"):
                E.scan(self.repo, cfg)  # an entry without the two fields is malformed

    def test_b2_anchored_segment_chains_are_parent_steps_in_every_position(self):
        # Root's round 3 of #33, B2: each spelling resolves like the relative path written out, pinned exactly.
        cases = {
            ('const d = path.join(__dirname, "..", "..", "lib", "x.mjs"); fork(d);', "mjs"): ["../../lib/x.mjs"],
            ('export default { test: { dir: path.join(__dirname, "..", "..") } };', "mjs"): ["../.."],
            ('const here = dirname(fileURLToPath(import.meta.url));\nnew Worker(path.resolve(here, "..", "s", "w.mjs"));',
             "mjs"): ["../s/w.mjs"],
            ('const a = join(import.meta.dirname, "..", "x.mjs");', "mjs"): ["../x.mjs"],
            ('x = os.path.join(os.path.dirname(__file__), "..", "lib")', "py"): ["../lib"],
            ('x = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")', "py"): ["../.."],
            ('HERE = os.path.dirname(__file__)\nx = os.path.join(HERE, "..", "w.py")', "py"): ["../w.py"],
            ('ROOT = Path(__file__).resolve().parents[2]', "py"): ["../.."],  # 1.5.2: the alias's own binding is no use
            ('w = Path(__file__).parent / ".." / "w.py"', "py"): ["../w.py"],
            ('w = Path(__file__).parent.parent / "w.py"', "py"): ["../w.py"],
            ('REPO = Path(__file__).resolve().parents[1]\ns = REPO / "scripts" / "x.sh"', "py"): ["..", "../scripts/x.sh"],
        }
        for (src, ext), want in cases.items():
            with self.subTest(src):
                self.assertEqual(E.anchored_chains(E.Source(src, ext)), want)
        for src, ext in (('d = path.join(__dirname, "lib", "x.mjs");', "mjs"), ('d = path.join(base, "..", "x");', "mjs"),
                         ('p = Path(__file__).parent / "w.py"', "py"), ('p = os.path.join(base, "..")', "py")):
            with self.subTest(control=src):
                self.assertEqual(E.anchored_chains(E.Source(src, ext)), [], "no parent step from the anchor: no chain")
        # In a scan: a Python root base by parents[N] refuses as a root climb when it is used other than joined with
        # string literals (1.5.2, root's ruling b); a bound base nobody uses reaches nothing.
        self.files(**{"services__a__t.py": "import subprocess\nfrom pathlib import Path\nROOT = Path(__file__).resolve().parents[2]\n"
                                           "subprocess.run(['make'], cwd=ROOT)\n"})
        with self.assertRaisesRegex(ValueError, r"services/a/t.py names \.\./\.\., the repository root or above it"):
            self.scan()
        self.files(**{"services__a__t.py": "from pathlib import Path\nROOT = Path(__file__).resolve().parents[2]\n"})
        self.scan()

    def test_one_batch_reader_serves_a_scans_revision_reads_byte_for_byte(self):
        # perf: one `git cat-file --batch` per scan, not one `git show` per file; the bytes are git show's exactly.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\r\n",
                      "scripts__bin.txt": "caf\u00e9\n"})
        (self.repo / "scripts/raw.txt").write_bytes(b"ok \xff\xfe\n")
        (self.repo / "scripts/x.mjs\r").write_text("CR TWIN\n")  # N1: --batch would drop the CR and read x.mjs
        os.symlink("x.mjs", self.repo / "scripts/link.mjs")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit",
                        "-qm", "r", "--no-gpg-sign"], check=True)
        rev = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        shown = lambda path: subprocess.run(["git", "-C", str(self.repo), "show", f"{rev}:{path}"], capture_output=True,
                                            check=True).stdout.decode("utf-8", errors="replace")
        real_popen, real_run, spawned, shows = subprocess.Popen, subprocess.run, [], []
        def counting(*a, **k):
            spawned.append(a[0])
            return real_popen(*a, **k)
        def run_counting(*a, **k):
            if "show" in a[0]:
                shows.append(a[0])
            return real_run(*a, **k)
        paths = ("scripts/x.mjs", "scripts/bin.txt", "scripts/raw.txt", "scripts/link.mjs", "scripts/x.mjs", "scripts/x.mjs\r")
        expected = {path: shown(path) for path in paths}  # before the counters go on
        with patch.object(E.subprocess, "Popen", counting), patch.object(E.subprocess, "run", run_counting), \
                E.batch_reads(self.repo, rev, env):
            for path in paths[:-1]:
                self.assertEqual(E.read_source(self.repo, path, rev, env), expected[path], path)
            self.assertEqual(len([c for c in spawned if "cat-file" in c]), 1, "one reader for every read")
            self.assertEqual(shows, [], "no per-file git show while the reader serves")
            self.assertEqual(E.read_source(self.repo, "scripts/x.mjs\r", rev, env), "CR TWIN\n", "a CR name is its own blob")
            self.assertEqual(len(shows), 1, "a CR cannot go through --batch: it falls back to git show")
            with self.assertRaisesRegex(ValueError, "cannot read scripts/gone.mjs at the scanned revision"):
                E.read_source(self.repo, "scripts/gone.mjs", rev, env)  # missing: falls back to git show, which refuses
            with self.assertRaisesRegex(ValueError, "cannot read scripts/a\nb at the scanned revision"):
                E.read_source(self.repo, "scripts/a\nb", rev, env)  # a newline cannot go through --batch
            # N2 (framing): the reads AFTER a refused name are still the reader's, byte for byte. Sent to --batch, the
            # newline name would be two requests, and every later read would get the previous one's answer.
            served = len(shows)
            for path in ("scripts/bin.txt", "scripts/raw.txt", "scripts/x.mjs"):
                self.assertEqual(E.read_source(self.repo, path, rev, env), expected[path], path)
            self.assertEqual(len(shows), served, "after a refused name the reader still serves every read")
            E._BLOB_READERS[(str(self.repo), rev)].proc.kill()
            E._BLOB_READERS[(str(self.repo), rev)].proc.wait()
            self.assertEqual(E.read_source(self.repo, "scripts/x.mjs", rev, env), expected["scripts/x.mjs"],
                             "a dead reader falls back to git show")
        self.assertNotIn((str(self.repo), rev), E._BLOB_READERS, "the reader closes with its scan")
        deps, _ = E.scan(self.repo, reviewed_cfg(IMPORT_CFG), revision=rev)  # a whole scan through the reader
        self.assertIn("a", deps)

    def test_the_backstop_counts_base_and_head_mentions(self):
        # Root's per-path ruling, condition (1): the flagged set is computed over BASE and HEAD. A PR that deletes the
        # only reader of tools/worker.mjs while changing it still plans that path FULL, since the deleted reader ran
        # it at the base; a reader the PR adds is a HEAD mention. The planner config is the BASE copy either way
        # (action.yml): the base tree is data like the head, and it can only add FULL paths, never remove one.
        def commit(message):
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid",
                            "commit", "-qm", message, "--no-gpg-sign"], check=True)
            return subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()

        cfg = reviewed_cfg(IMPORT_CFG)
        cfg["extra_edges"] = {"tools/worker.mjs": ["a"]}
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
        runner = 'import { execFileSync } from "node:child_process";\nexecFileSync(process.execPath, ["tools/worker.mjs"]);\n'
        self.files(**{"services__a__t.mjs": 'import "../../tools/worker.mjs";\n', "tools__worker.mjs": "export {};\n",
                      "services__c__t.test.mjs": runner})
        base = commit("base: c runs tools/worker.mjs")
        (self.repo / "services/c/t.test.mjs").unlink()
        (self.repo / "tools/worker.mjs").write_text("export const changed = 1;\n")
        head = commit("head: the PR deletes c's runner and changes worker.mjs")

        def flagged(*extra):
            out = self.repo / ".git" / "readers.json"
            with redirect_stdout(io.StringIO()):
                rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo), "--revision", head,
                             "--out-json", str(out), *extra])
            return rc, json.loads(out.read_text())["backstop_full"]

        self.assertEqual(flagged(), (0, []), "control: HEAD alone no longer names the deleted reader")
        self.assertEqual(flagged("--base-revision", base), (0, ["tools/worker.mjs"]), "BASE: the deleted reader counts")
        (self.repo / "services/c/t.test.mjs").write_text(runner)
        head = commit("head: the PR adds the reader back")
        self.assertEqual(flagged()[1], ["tools/worker.mjs"], "a reader the PR adds is a HEAD mention")
        with self.assertRaisesRegex(ValueError, "base revision must be an immutable commit"):
            flagged("--base-revision", "main")

    def _commit(self, repo, message):
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit", "-qm",
                        message, "--no-gpg-sign"], check=True)
        return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

    def _flagged(self, repo, head, *extra):
        out = Path(tempfile.mkdtemp()) / "readers.json"
        with redirect_stdout(io.StringIO()):
            rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(repo), "--revision", head,
                         "--out-json", str(out), *extra])
        return rc, json.loads(out.read_text())["backstop_full"]

    def test_the_subjects_are_both_trees_a_deleted_or_moved_p_still_counts(self):
        # Root's condition on the base-only reduction: the SUBJECT side is BASE ∪ HEAD. The PR deletes (or renames) mapped
        # tools/old.mjs; an UNCHANGED file of package c still runs it by name, so the head pass must test that mention.
        cfg = reviewed_cfg(IMPORT_CFG)
        cfg["extra_edges"] = {"tools/**": ["a"]}
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
        self.files(**{"services__a__t.mjs": 'import "../../tools/old.mjs";\n', "tools__old.mjs": "export {};\n",
                      "services__c__run.test.mjs": 'import { execFileSync } from "node:child_process";\n'
                                                   'execFileSync(process.execPath, ["tools/old.mjs"]);\n'})
        base = self._commit(self.repo, "base")
        for how in ("delete", "rename"):
            with self.subTest(how):
                subprocess.run(["git", "-C", str(self.repo), "checkout", "-q", base], check=True)
                (self.repo / "services/a/t.mjs").write_text("export {};\n")
                if how == "delete":
                    (self.repo / "tools/old.mjs").unlink()
                else:
                    (self.repo / "tools/old.mjs").rename(self.repo / "tools/new.mjs")
                head = self._commit(self.repo, how)
                self.assertNotIn("tools/old.mjs", self._flagged(self.repo, head)[1], "control: HEAD alone has no old.mjs")
                self.assertIn("tools/old.mjs", self._flagged(self.repo, head, "--base-revision", base)[1],
                              "a P only BASE maps, named by an unchanged file, is a subject")

    def test_a_blobless_candidate_reads_the_base_side_from_the_sparse_base_checkout(self):
        # vagaris checks out `filter: blob:none`, so its candidate holds no base blobs (and the scan never fetches). The
        # base pass reads the PR's deleted and modified files from the action's sparse base checkout instead.
        cfg = reviewed_cfg(IMPORT_CFG)
        cfg["extra_edges"] = {"tools/worker.mjs": ["a"]}
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
        runner = 'import { execFileSync } from "node:child_process";\nexecFileSync(process.execPath, ["tools/worker.mjs"]);\n'
        self.files(**{"services__a__t.mjs": 'import "../../tools/worker.mjs";\n', "tools__worker.mjs": "export {};\n",
                      "services__c__t.test.mjs": runner})
        base = self._commit(self.repo, "base")
        (self.repo / "services/c/t.test.mjs").unlink()
        (self.repo / "tools/worker.mjs").write_text("export const changed = 1;\n")
        head = self._commit(self.repo, "head")
        subprocess.run(["git", "-C", str(self.repo), "config", "uploadpack.allowFilter", "true"], check=True)
        work = Path(tempfile.mkdtemp())
        cand, basechk = work / "cand", work / "base"
        url = "file://" + str(self.repo)
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, str(cand)], check=True)
        subprocess.run(["git", "-C", str(cand), "checkout", "-q", head], check=True)
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, str(basechk)], check=True)
        subprocess.run(["git", "-C", str(basechk), "sparse-checkout", "set", "--no-cone", "/.github/ci-plan.json",
                        "/services/c/t.test.mjs", "/tools/worker.mjs"], check=True)
        subprocess.run(["git", "-C", str(basechk), "checkout", "-q", base], check=True)
        with self.assertRaisesRegex(ValueError, "the base tree's changed files could not be read"):
            self._flagged(cand, head, "--base-revision", base)  # control: the candidate holds no base blobs
        self.assertEqual(self._flagged(cand, head, "--base-revision", base, "--base-repo", str(basechk)),
                         (0, ["tools/worker.mjs"]))

    def test_a_grep_that_cannot_read_a_blob_refuses_instead_of_missing(self):
        # git grep exits 1 ("no match") when a blob is absent (a partial clone, no lazy fetch) and prints only
        # `unable to read`. Every grep of the scan treats that as a refusal, never as a clean miss.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        head = self._commit(self.repo, "head")
        subprocess.run(["git", "-C", str(self.repo), "config", "uploadpack.allowFilter", "true"], check=True)
        cand = Path(tempfile.mkdtemp()) / "cand"
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", "file://" + str(self.repo), str(cand)],
                       check=True)
        subprocess.run(["git", "-C", str(cand), "sparse-checkout", "set", "--no-cone", "/scripts/"], check=True)
        subprocess.run(["git", "-C", str(cand), "checkout", "-q", head], check=True)  # services/a/t.mjs: no blob
        with self.assertRaisesRegex(ValueError, "reader closure unproven: the reader scan could not read the scanned tree"):
            E.scan(cand, reviewed_cfg(IMPORT_CFG), revision=head)
        deps, _ = E.scan(self.repo, reviewed_cfg(IMPORT_CFG), revision=head)  # control: every blob present
        self.assertIn("a", deps)

    def test_both_unreadable_signals_refuse_typed_whatever_the_git_version(self):
        # git 2.50 prints `unable to read` and exits 1; git 2.56 exits 128 (#47's planner-tests, 2026-10-29). Both are a
        # typed refusal with git's first stderr line; 0 (a match) and 1 with a clean stderr (no match) are not.
        run = lambda rc, err=b"": subprocess.CompletedProcess(["git", "grep"], rc, b"", err)
        for out, detail in ((run(1, b"error: 'HEAD:a.mjs': unable to read 1234\n"), "git grep exit 1: error: 'HEAD:a.mjs': unable to read 1234"),
                            (run(128, b"fatal: missing blob object 'abcd'\n"), "git grep exit 128: fatal: missing blob object 'abcd'"),
                            (run(2), "git grep exit 2")):
            with self.assertRaises(ValueError) as caught:
                E.grep_read_everything(out, "the reader scan")
            self.assertEqual(str(caught.exception), "unresolved (reader closure unproven: the reader scan could not read "
                                                    f"the scanned tree ({detail}))")
        for out in (run(0), run(1)):
            E.grep_read_everything(out, "the reader scan")  # control: a match, and a clean miss, are read

    def test_a_grep_git_cannot_run_on_its_revision_refuses_typed_not_a_crash(self):
        # Root's control, the local rc-128 path: real git grep on a revision that does not exist exits 128, as git 2.56
        # does for an unreadable blob. The pass refuses typed with git's own line; it never crashes into FULL.
        self.files(**{"a.mjs": "export const x = 1;\n"})
        self._commit(self.repo, "head")
        out = subprocess.run(["git", "-C", str(self.repo), "grep", "--no-color", "-I", "-e", "x", "f" * 40, "--"],
                             capture_output=True, env={**os.environ, "LC_ALL": "C"})
        self.assertEqual(out.returncode, 128)
        with self.assertRaisesRegex(ValueError, r"reader closure unproven: the reader scan could not read the scanned tree "
                                                r"\(git grep exit 128: fatal: "):
            E.grep_read_everything(out, "the reader scan")

    def test_base_paths_name_exactly_the_deleted_and_modified_files_for_the_sparse_base_checkout(self):
        # The action adds these patterns to its sparse base checkout; each must check out exactly its own file, whatever
        # characters the name holds (gitignore syntax), and an added file is not one (the base has no such file).
        names = ["services/a/x.mjs", "odd/*star?[x].txt", "odd/!bang", "odd/#hash", "odd/trail  ", "odd/back\\slash",
                 "odd/sp ace.js", "gone.mjs"]
        self.files(**{n.replace("/", "__"): "v1\n" for n in names + ["kept.txt", "odd/starXx].txt"]})
        base = self._commit(self.repo, "base")
        for n in names[:-1]:
            (self.repo / n).write_text("v2\n")
        (self.repo / "gone.mjs").unlink()
        (self.repo / "added.mjs").write_text("new\n")
        head = self._commit(self.repo, "head")
        self.assertEqual(E.base_paths(self.repo, base, head), sorted(names))
        out = Path(tempfile.mkdtemp()) / "out"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(E.main(["base-paths", "--repo", str(self.repo), "--base-revision", base, "--revision", head,
                                     "--github-output", str(out)]), 0)
        lines = out.read_text().split("\n")
        self.assertTrue(lines[0].startswith("paths<<EOF_") and lines[-2] == lines[0][len("paths<<"):])
        patterns = lines[1:-2]
        chk = Path(tempfile.mkdtemp()) / "chk"
        subprocess.run(["git", "clone", "-q", "--no-checkout", str(self.repo), str(chk)], check=True)
        subprocess.run(["git", "-C", str(chk), "sparse-checkout", "set", "--no-cone", "--stdin"],
                       input="\n".join(patterns) + "\n", text=True, check=True)
        subprocess.run(["git", "-C", str(chk), "checkout", "-q", base], check=True)
        present = sorted(str(p.relative_to(chk)) for p in chk.rglob("*") if p.is_file() and ".git" not in p.parts)
        self.assertEqual(present, sorted(names), "each pattern checks out exactly its own file")

    def test_a_pass_that_times_out_is_a_typed_refusal(self):
        # F18 (root, 2026-10-29): census part 2 of #33 round 4 timed the directory pass out on vagary-core, and the
        # TimeoutExpired escaped `check` uncaught. Any pass's timeout is now a refusal (FULL), named as one.
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        real, greps = subprocess.run, []
        def slow_grep(*a, **k):
            if "grep" in a[0]:
                greps.append(k.get("timeout"))
                raise subprocess.TimeoutExpired(a[0], k.get("timeout", 0))
            return real(*a, **k)
        with patch.object(E.subprocess, "run", slow_grep):
            with self.assertRaisesRegex(ValueError, r"reader scan timed out: `git grep` ran over its 15 s limit on both "
                                                    r"attempts; reader closure unproven"):
                E.scan(self.repo, reviewed_cfg(IMPORT_CFG))
        self.assertEqual(greps, [15, 15], "1.7.3: one retry after a timeout, at the unscaled ceiling")

    def test_a_git_call_that_times_out_once_is_retried(self):
        """1.7.3 (spine, core #936): a loaded runner's one slow `git grep` no longer costs the reduced plan."""
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        want = E.scan(self.repo, reviewed_cfg(IMPORT_CFG))
        real, greps = subprocess.run, []
        def slow_once(*a, **k):
            if "grep" in a[0]:
                greps.append(list(a[0]))
                if len(greps) == 1:
                    raise subprocess.TimeoutExpired(a[0], k.get("timeout", 0))
            return real(*a, **k)
        with patch.object(E.subprocess, "run", slow_once):
            self.assertEqual(E.scan(self.repo, reviewed_cfg(IMPORT_CFG)), want)
        self.assertEqual(greps[0], greps[1], "the timed-out `git grep` is retried once, then the scan goes on")

    def test_check_exits_3_on_a_reader_timeout(self):
        """A reader-scan timeout is its own exit, so the action names it ("reader scan timed out") instead of folding it
        into "reader closure unproven"; any other refusal is unchanged."""
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github/ci-plan.json").write_text(json.dumps(reviewed_cfg(IMPORT_CFG)))
        real = subprocess.run
        def slow_grep(*a, **k):
            if "grep" in a[0]:
                raise subprocess.TimeoutExpired(a[0], k.get("timeout", 0))
            return real(*a, **k)
        buf = io.StringIO()
        with patch.object(E.subprocess, "run", slow_grep), redirect_stdout(buf):
            rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(self.repo)])
        self.assertEqual(rc, 3)
        self.assertIn("FAIL unresolved (reader scan timed out: `git grep`", buf.getvalue())

    def test_the_action_names_a_reader_timeout(self):
        text = (Path(__file__).with_name("action.yml")).read_text()
        step = text.split("id: readers", 1)[1].split("    - name:", 1)[0]
        self.assertIn('if [ "$rc" -eq 3 ]; then', step)
        self.assertIn('reason="reader scan timed out; full validation required"', step)
        self.assertIn('elif [ "$rc" -ne 0 ]; then\n            reason="reader closure unproven; full validation required"', step)
        self.assertEqual(text.count("CHANGE_IMPACT_GIT_TIMEOUT_SCALE: ${{ inputs.git-timeout-scale }}"), 4,
                         "every step that runs plan.py or edges.py gets the scale")

    def test_the_action_judges_the_candidate_with_the_base_config_only(self):
        # A PR cannot use its own new registry entries: action.yml runs `check` with the BASE copy of the config and the
        # base manifests, never the candidate's (root's ruling on #33 round 3).
        text = (Path(__file__).with_name("action.yml")).read_text()
        call = text.split('"$GITHUB_ACTION_PATH/edges.py" check', 1)[1].split("; then", 1)[0]
        self.assertIn('--config "$STATE/base/$CONFIG"', call)
        self.assertIn('--manifest-root "$STATE/base"', call)
        self.assertIn('--repo "$GITHUB_WORKSPACE/$CANDIDATE_ROOT" --revision "$CANDIDATE"', call)
        # The backstop's BASE side: the base revision, read from the sparse base checkout that holds the PR's deleted and
        # modified files (base-paths), never from the candidate, which may hold no base blobs.
        self.assertIn('--base-revision "$POLICY_REF" --base-repo "$STATE/base"', call)
        self.assertIn("${{ steps.changed.outputs.paths }}", text.split("name: Base commit manifests and plan config", 1)[1]
                      .split("    - name:", 1)[0])
        self.assertIn('edges.py" base-paths --repo "$GITHUB_WORKSPACE/$CANDIDATE_ROOT"', text)
        self.assertEqual(text.count('edges.py" check'), 1, "one check call, so no other path reads a candidate config")

    def test_d5_a_leading_slash_is_stripped_so_a_cwd_concat_escapes(self):
        # N2: `process.cwd() + "/scripts/x.mjs"` names scripts/, a top-level directory outside every package.
        for expr in ('process.cwd() + "/scripts/x.mjs"', 'path.join(process.cwd(), "/scripts/x.mjs")'):
            for reach in ("package", "external", ["scripts/x.mjs"]):
                with self.subTest(expr, reach=reach):
                    self.files(**{"services__a__load.mjs": f"export const load = () => import({expr});\n",
                                  "scripts__x.mjs": "export {};\n"})
                    cfg = json.loads(json.dumps(IMPORT_CFG))
                    cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/load.mjs", "expr": expr, "reach": reach}]
                    with self.assertRaisesRegex(ValueError, "steps outside its package"):
                        self.scan(cfg)

    def test_d5_a_reader_directory_reacher_keeps_its_job_selected_or_the_path_unmapped(self):
        # N3: test/foo.test.mjs (reader dir test/, job root) imports scripts/x.mjs, as package a does. Mapping
        # scripts/x.mjs to [a] alone selected a and skipped the root job that runs foo.test.mjs.
        self.files(**{"test__foo.test.mjs": 'import "../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n",
                      "services__a__t.mjs": 'import "../../scripts/x.mjs";\n'})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["reader_dirs"] = ["scripts", "tools", "test"]
        cfg["extra_edges"] = {"scripts/x.mjs": ["a"]}
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        _, _, report = self.scan(cfg)
        # test/ reaches it, and scripts/ holds it (a reader-dir file may itself be an executor its job runs).
        self.assertEqual(report["unit_imports"]["scripts/x.mjs"], ["scripts", "test"])
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("narrowed import: scripts/x.mjs is reached from test/, which reader job 'root' runs", out)
        for rule in ({"packages": ["a"]}, "always", "any_package"):
            with self.subTest(rule=rule):
                cfg["jobs"] = {"root": rule}
                rc, out = self.check(cfg)
                self.assertNotIn("narrowed import", out)
        # Unmapped, the path plans FULL, which runs every job: no narrowing (the package importer's own rule still asks).
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        cfg["extra_edges"] = {}
        self.assertNotIn("narrowed import", self.check(cfg)[1])
        # A reacher in no reader directory runs in no declared job: nothing it reaches may be mapped.
        self.files(**{"misc__run.mjs": 'import "../scripts/x.mjs";\n'})
        cfg["extra_edges"] = {"scripts/x.mjs": ["a"]}
        cfg["jobs"] = {"root": "always"}
        self.assertIn("is reached by a file outside every package and every reader directory", self.check(cfg)[1])

    def test_d5_a_relative_path_at_or_above_the_repository_root_refuses(self):
        # N4: a vitest alias "@root" -> "../.." (or baseUrl "../..") reaches every file; it was dropped.
        for spec in ('alias: { "@root": "../.." }', 'baseUrl: "../../.."', 'root: "../../"'):
            with self.subTest(spec):
                self.files(**{"services__a__vitest.config.mjs": f"export default {{ {spec} }};\n"})
                with self.assertRaisesRegex(ValueError, "the repository root or above it"):
                    self.scan()
                self.files(**{"services__a__vitest.config.mjs": "export default {};\n"})

    def test_d5_an_importing_file_type_the_scan_does_not_parse_refuses_when_reached(self):
        # N5: .mdx, .astro, .vue and .svelte files import modules; the closure treated them as inert data.
        for ext in ("mdx", "astro", "vue", "svelte"):
            with self.subTest(ext):
                self.files(**{f"tools__page.{ext}": 'import X from "./x.mjs";\n', "tools__x.mjs": "export {};\n",
                              "services__a__t.mjs": f'import "../../tools/page.{ext}";\n'})
                with self.assertRaisesRegex(ValueError, f"tools/page.{ext}, a .{ext} file that can import modules"):
                    self.scan()
                self.files(**{"services__a__t.mjs": "export {};\n"})

    # ── Root's regression vectors for the delta at 7b83bf159e (lanes/root/reviews/dotgithub-33.md), each EXACT. Common
    # fixture: packages a, b and c under services/; the reader job root has {packages: [b]}.
    def root_b_cfg(self):
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["edge_scan"]["reader_dirs"] = ["scripts", "test", "tools"]
        cfg["jobs"] = {"root": {"packages": ["b"]}}
        return cfg

    def test_root_vector_r1_a_reader_dir_executor_keeps_root_selected(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.js";\n', "test__foo.test.mjs": 'import "../scripts/x.js";\n',
                      "scripts__x.ts": "export const x = 1;\n"})
        cfg = self.root_b_cfg()
        _, _, report = self.scan(cfg)
        self.assertEqual(report["imports"]["scripts/x.ts"], ["a"])
        self.assertEqual(report["unit_imports"]["scripts/x.ts"], ["scripts", "test"])
        cfg["extra_edges"] = {"scripts/x.ts": ["a"]}  # exactly the mapping the package importer asks for
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("narrowed import: scripts/x.ts is reached from scripts/, which reader job 'root' runs", out)
        self.assertIn("narrowed import: scripts/x.ts is reached from test/, which reader job 'root' runs", out)
        cfg["extra_edges"] = {"scripts/x.ts": ["a", "b"]}  # a mapping that runs root: no narrowing
        self.assertNotIn("narrowed import", self.check(cfg)[1])

    def test_root_vector_r1b_an_executor_beside_the_module_keeps_root_selected(self):
        self.files(**{"services__a__t.mjs": 'import "../../scripts/x.js";\n', "test__foo.test.mjs": 'import "../scripts/x.js";\n',
                      "scripts__x.ts": "export const x = 1;\n", "scripts__x.test.mjs": 'import "./x.js";\n'})
        cfg = self.root_b_cfg()
        _, _, report = self.scan(cfg)
        self.assertEqual(report["unit_imports"]["scripts/x.ts"], ["scripts", "test"])
        cfg["extra_edges"] = {"scripts/x.ts": ["a"]}
        rc, out = self.check(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("narrowed import: scripts/x.ts is reached from scripts/", out)

    def test_root_vector_b3c_a_leading_slash_escape_refuses_under_every_reach(self):
        for reach in ("external", "package", "fixture"):
            with self.subTest(reach=reach):
                self.files(**{"services__a__t.mjs": 'export const l = () => import(process.cwd() + "/scripts/x.mjs");\n',
                              "services__c__t.mjs": 'import "../../scripts/x.mjs";\n', "scripts__x.mjs": "export {};\n"})
                cfg = self.root_b_cfg()
                cfg["edge_scan"]["computed_imports"] = [{"file": "services/a/t.mjs",
                                                         "expr": 'process.cwd() + "/scripts/x.mjs"', "reach": reach}]
                with self.assertRaisesRegex(ValueError, r'steps outside its package: `process.cwd\(\) \+ "/scripts/x.mjs"`'):
                    self.scan(cfg)

    def test_root_vector_n1_every_spelling_of_a_build_output_load_refuses(self):
        spellings = ["timeout 300 node ../dist/x.js", "npx tsx ../dist/x.js", "env -i node ../dist/x.js",
                     "node --import ./reg.mjs ../dist/x.js", "pnpm exec node ../dist/x.js", "xargs node ../dist/x.js",
                     "nohup node ../dist/x.js", "node --input-type=module <<'EOF'\nimport \"../dist/x.js\";\nEOF"]
        for line in spellings:
            with self.subTest(line):
                self.files(**{"services__a__package.json": '{"scripts": {"test": "bash ../../tools/run.sh"}}\n',
                              "tools__run.sh": "#!/bin/bash\n" + line + "\n", "tools__reg.mjs": "export {};\n",
                              "scripts__x.ts": "export const x = 1;\n", "services__c__t.mjs": 'import "../../scripts/x.js";\n'})
                with self.assertRaisesRegex(ValueError, r"\(tools/run.sh names dist/x.js, which is no tracked file or directory"):
                    self.scan(self.root_b_cfg())
        self.files(**{"tools__run.sh": "#!/bin/bash\n", "services__a__package.json": "{}\n"})
        for js in ('fork("../../dist/x.js");', 'new Worker("../../dist/x.js");', 'spawn(process.execPath, ["../../dist/x.js"]);'):
            with self.subTest(js):
                self.files(**{"services__a__w.mjs": js + "\n"})
                with self.assertRaisesRegex(ValueError, r"\(services/a/w.mjs names dist/x.js, which is no tracked file or directory"):
                    self.scan(self.root_b_cfg())
        self.files(**{"services__a__w.mjs": "export {};\n"})

    def test_root_vector_r8_a_root_alias_or_base_url_refuses(self):
        for name, body in (("vitest.config.mjs", 'export default { resolve: { alias: { "@root": path.resolve(__dirname, "../..") } } };\n'),
                           ("tsconfig.json", '{"compilerOptions": {"baseUrl": "../.."}}\n')):
            with self.subTest(name):
                self.files(**{f"services__a__{name}": body, "services__a__t.test.mjs": 'import "@root/scripts/x.js";\n',
                              "scripts__x.ts": "export const x = 1;\n", "services__c__t.mjs": 'import "../../scripts/x.js";\n'})
                with self.assertRaisesRegex(ValueError, r"services/a/" + re.escape(name) + r" names \.\./\.\., the repository root or above it"):
                    self.scan(self.root_b_cfg())
                (self.repo / "services/a" / name).unlink()
                subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)

    def test_root_vector_n5_an_unparsed_importing_page_refuses(self):
        for ext in ("mdx", "astro", "vue", "svelte"):
            with self.subTest(ext):
                self.files(**{"services__a__t.mjs": f'import "../../tools/content/page.{ext}";\n',
                              f"tools__content__page.{ext}": 'import W from "./widget.js";\n',
                              "tools__content__widget.ts": "export const w = 1;\n",
                              "services__c__t.mjs": 'import "../../tools/content/widget.js";\n'})
                with self.assertRaisesRegex(ValueError, rf"a reaches tools/content/page.{ext}, a .{ext} file that can import modules"):
                    self.scan(self.root_b_cfg())
                (self.repo / f"tools/content/page.{ext}").unlink()
                self.files(**{"services__a__t.mjs": "export {};\n"})

    # ── 1.5.2: a shell script's relative paths resolve where it has `cd`'d to (spine's A2 census, FALSE-POSITIVES item 3)
    def test_shell_cd_to_its_own_directory_moves_where_relative_paths_resolve(self):
        base = {"scripts__ci-test-pg.sh": "#!/bin/bash\necho pg\n", "scripts__x.sh": "#!/bin/bash\n"}
        cases = {
            # spine's 22 runners: cd up from test/, then a path written relative to the package directory.
            "runner": ('cd "$(dirname "$0")/.."\nPGPORT="$(bash ../../scripts/ci-test-pg.sh port)"\n', "scripts/ci-test-pg.sh"),
            "same line": ('cd "$(dirname "$0")/.." && bash ../../scripts/ci-test-pg.sh wait\n', "scripts/ci-test-pg.sh"),
            "BASH_SOURCE": ('cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2\nbash ../../scripts/x.sh\n', "scripts/x.sh"),
            "conditional": ('[ -d .git ] && cd "$(dirname "$0")/.."\nbash ../../scripts/x.sh\n', "scripts/x.sh"),
            "before the cd": ('bash ../../../scripts/x.sh\ncd "$(dirname "$0")/.."\n', "scripts/x.sh"),
            "identity control": ('bash "$(dirname "$0")/../../../scripts/ci-test-pg.sh" wait\n', "scripts/ci-test-pg.sh"),
            "heredoc text": ('cat <<EOF\ncd /tmp\nEOF\nbash ../../../scripts/x.sh\n', "scripts/x.sh"),
            # vagary-core social-distribution's runner: a trailing comment after the cd is no part of its argument.
            "trailing comment": ('cd "$(dirname "$0")/.."          # services/a\nbash ../../scripts/x.sh\n', "scripts/x.sh"),
            "a comment's cd": ('echo start  # cd /tmp\nbash ../../../scripts/x.sh\n', "scripts/x.sh"),
        }
        for why, (body, target) in cases.items():
            with self.subTest(why):
                self.files(**base, **{"services__a__test__run.sh": "#!/bin/bash\n" + body})
                _, _, report = self.scan()
                self.assertIn("a", report["imports"].get(target, []), why)

    def test_shell_a_cd_the_scan_cannot_follow_refuses_later_relative_paths(self):
        for why, body in {"computed": 'cd "$WORKDIR"\nbash ../x.sh\n', "literal": "cd ../x.sh.d\nbash ./x.sh\n",
                          "absolute": "cd /opt/app\nbash ../x.sh\n", "no argument": "cd\nbash ../x.sh\n",
                          "dash": "cd -\nbash ../x.sh\n",
                          "a quoted #": 'cd "../#tools"\nbash ../x.sh\n'}.items():
            with self.subTest(why):
                self.files(**{"services__a__test__run.sh": "#!/bin/bash\n" + body, "services__a__x.sh": "#!/bin/bash\n",
                              "services__a__x.sh.d__keep.txt": "k\n"})
                with self.assertRaisesRegex(ValueError, "after a `cd` the scan cannot follow"):
                    self.scan()
        # A relative path BEFORE such a cd still resolves from the file's directory.
        self.files(**{"services__a__test__run.sh": "#!/bin/bash\nbash ../../../scripts/x.sh\ncd \"$WORKDIR\"\necho done\n",
                      "scripts__x.sh": "#!/bin/bash\n"})
        self.assertIn("a", self.scan()[2]["imports"]["scripts/x.sh"])

    def test_shell_whole_file_pass_reads_the_scanned_revision(self):
        # action.yml runs `check --revision`: the whole-file shell pass lists the commit's shell files (ls-tree takes no
        # glob and no `:!` exclude, exit 128), and reads the committed bytes, never a later working tree.
        self.files(**{"services__a__test__run.sh": '#!/bin/bash\ncd "$(dirname "$0")/.."\nbash ./x.sh\n',
                      "services__a__x.sh": "#!/bin/bash\n", "scripts__x.sh": "#!/bin/bash\n",
                      "docs__note.sh": "cd /tmp\nbash ./y.sh\n"})  # excluded (docs): it would refuse if listed
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit",
                        "-qm", "r", "--no-gpg-sign"], check=True)
        rev = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        (self.repo / "services/a/test/run.sh").write_text("#!/bin/bash\ncd /tmp\nbash ./x.sh\n")  # the working tree differs
        report = {}
        E.scan(self.repo, IMPORT_CFG, revision=rev, report=report)
        with self.assertRaisesRegex(ValueError, "after a `cd` the scan cannot follow"):
            E.scan(self.repo, IMPORT_CFG)

    def test_shell_any_other_cd_names_the_directory_its_next_commands_run_in(self):
        # R5V14: only a cd to the script's own directory is modelled (shell_cwd_spans); any other cd's argument is read.
        self.files(**{"services__a__test__run.sh": "#!/bin/bash\n(cd ../../b && make)\n", "services__b__Makefile": "all:\n"})
        self.assertIn("b", self.scan()[0]["a"])
        # A `../` after a computed prefix resolves from the file's directory, as in any other file: naming nothing refuses.
        self.files(**{"services__a__test__run.sh": '#!/bin/bash\nfor d in x; do (cd "$d/../../packages/b" && make); done\n'})
        with self.assertRaisesRegex(ValueError, "which is no tracked file or directory"):
            self.scan()

    def test_shell_a_reached_unowned_script_resolves_after_its_own_cd(self):
        # tools/run.sh (outside every package) is reached from a; it cds to the repo root, then runs ./scripts/x.sh.
        self.files(**{"services__a__t.mjs": 'import "../../tools/run.sh";\n',
                      "tools__run.sh": '#!/bin/bash\ncd "$(dirname "$0")/.."\nbash ./scripts/x.sh\n',
                      "scripts__x.sh": '#!/bin/bash\ncat services/b/data.json\n', "services__b__data.json": "{}\n"})
        deps, _, report = self.scan()
        self.assertIn("a", report["imports"]["scripts/x.sh"])

    def test_an_unowned_js_caller_declares_a_top_level_literal_after_a_computed_base(self):
        # spine's FALSE-POSITIVES item 4: e2e/adr179/journeys.mjs imports join(identityDir, 'test', 'x.mjs'), where 'test'
        # is a top-level reader directory. From outside every package that is a load to declare, not an escape.
        expr = "pathToFileURL(join(identityDir, 'test', 'webauthn-authenticator.mjs')).href"
        self.files(**{"e2e__adr179__journeys.mjs": f"export const load = (identityDir) => import({expr});\n",
                      "services__identity__test__webauthn-authenticator.mjs": "export {};\n", "test__keep.txt": "k\n"})
        cfg = json.loads(json.dumps(IMPORT_CFG))
        cfg["workspace"]["packages"]["identity"] = {"dir": "services/identity", "deps": []}
        cfg["edge_scan"]["reader_dirs"] = ["scripts", "tools", "e2e", "test"]
        with self.assertRaisesRegex(ValueError, "undeclared computed import"):
            self.scan(cfg)
        cfg["edge_scan"]["computed_imports"] = [{"file": "e2e/adr179/journeys.mjs", "expr": expr,
                                                 "reach": ["services/identity/test/webauthn-authenticator.mjs"]}]
        _, readers, _ = self.scan(cfg)
        self.assertIn("identity", readers["e2e"])
        # The same expression in a PACKAGE still escapes, declared or not; so does a parent step from outside.
        self.files(**{"services__a__load.mjs": f"export const load = (identityDir) => import({expr});\n"})
        cfg["edge_scan"]["computed_imports"].append({"file": "services/a/load.mjs", "expr": expr, "reach": "external"})
        with self.assertRaisesRegex(ValueError, "steps outside its package"):
            self.scan(cfg)

    def test_an_untracked_name_under_a_directory_reached_whole_adds_nothing(self):
        # spine's FALSE-POSITIVES item 5: a's package.json depends on file:../../shared/sdk, which reaches that directory
        # whole; the SDK's own test imports its untracked build output ../dist/server.js. Every tracked file the build
        # compiles dist/ from is already credited, so the name adds nothing.
        self.files(**{"services__a__package.json": '{"dependencies": {"sdk": "file:../../shared/sdk"}}\n',
                      "services__a__x.mjs": "export {};\n",
                      "shared__sdk__src__server.ts": "export const s = 1;\n",
                      "shared__sdk__test__app.mjs": 'import "../dist/server.js";\n'})
        _, _, report = self.scan()
        self.assertIn("a", report["imports"]["shared/sdk/src/server.ts"])
        # Reached only through the test file, the name still stands for shared/sdk, the directory it shares with its namer.
        self.files(**{"services__a__package.json": '{"name": "a"}\n', "services__a__t.mjs": 'import "../../shared/sdk/test/app.mjs";\n'})
        _, _, report = self.scan()
        self.assertIn("a", report["imports"]["shared/sdk/src/server.ts"])
        # A name sharing only a top-level directory with its namer refuses: shared/dist/x.js from shared/tools/run.mjs.
        self.files(**{"shared__tools__run.mjs": 'import "../dist/x.js";\n', "services__a__u.mjs": 'import "../../shared/tools/run.mjs";\n'})
        with self.assertRaisesRegex(ValueError, "names shared/dist/x.js, which is no tracked file or directory"):
            self.scan()

    def test_adversarial_forms_aimed_at_the_rule(self):
        self.files(**{
            # CRLF: the whole-file read must still find the ./ import.
            "services__a__t.mjs": 'import "../../scripts/crlf.mjs";\r\n',
            "scripts__crlf.mjs": 'import "./tail.mjs";\r\nexport {};\r\n',
            "scripts__tail.mjs": 'export const t = "services/b/t.json";\r\n',
            # A top-level directory whose name extends a package directory's: outside every package, so an edge.
            "services__b__t.mjs": 'import "../../services-x/u.mjs";\n',
            "services-x__u.mjs": 'export const u = "services/c/u.json";\n',
            # The root package.json is a file outside every package: a data target.
            "services__c__t.mjs": 'read("../../package.json");\n',
            "package.json": '{"scripts": {"t": "pytest services/a"}}\n',
        })
        deps, _, report = self.scan()
        self.assertEqual((deps["a"], deps["b"], deps["c"]), ({"b"}, {"c"}, {"a"}))
        self.assertIn("services-x/u.mjs", report["imports"])


class VectorHarness:
    """Root's method for a vector: commit the fixture; run the real `check --revision`; apply check's own remedies (the
    importers it names, a package the reader job lists, leaving an <unmapped> path unmapped, the backstop's owner or
    full_globs, a declared dep) until rc 0; then judge the change with the real plan.classify_paths + rule_matches."""

    def setUp(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        isolated = patch.dict(os.environ, environment, clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)

    REMEDIES = (
        (r"undeclared import edge: (\S+) imports (\S+) ", lambda c, m: E_add(c, m.group(2), m.group(1))),
        (r"narrowed import: (\S+) is reached from \S+/, which reader job", lambda c, m: E_add(c, m.group(1), c["jobs"]["root"]["packages"][0])
         if isinstance(c["jobs"]["root"], dict) else False),
        (r"narrowed import: (\S+) is reached by a file outside every package and every reader",
         lambda c, m: c.setdefault("extra_edges", {}).pop(m.group(1), None) is not None),
        (r"unattributed mention: \S+ \(package (\S+)\) names \S+, but the mapping for (\S+) selects",
         lambda c, m: E_add(c, m.group(2), m.group(1))),
        (r"unattributed mention: \S+, outside every package, names \S+ by a route the scan did not record, so whatever "
         r"runs \S+ may run (\S+) ", lambda c, m: E_list_add(c.setdefault("full_globs", []), m.group(1))),
        (r"inert mention: \S+ names \S+, but inert_globs '[^']*' makes a change to (\S+) select nothing",
         lambda c, m: E_list_add(c.setdefault("full_globs", []), m.group(1))),
        (r"undeclared read: (\S+) reads (\S+) ", lambda c, m: E_list_add(c["workspace"]["packages"][m.group(1)]["deps"], m.group(2))),
        (r"\S+/ reads (\S+), but job '(\S+)' does not list it",
         lambda c, m: isinstance(c["jobs"][m.group(2)], dict) and E_list_add(c["jobs"][m.group(2)]["packages"], m.group(1))),
    )

    def run_case(self, case):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        repo = Path(td.name)
        for d in ("services/a", "services/b", "services/c", ".github"):
            (repo / d).mkdir(parents=True, exist_ok=True)
            (repo / d / "keep.txt").write_text("k\n")
        for path, text in case["files"].items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text)
        for path, data in case.get("binary", {}).items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_bytes(base64.b64decode(data))
        for path, target in case.get("symlinks", {}).items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, repo / path)
        cfg = {**json.loads(json.dumps(self.CASES["base_config"])), **json.loads(json.dumps(case["cfg_set"]))}
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        for path in case.get("gitlinks", []):  # a submodule commit; its contents are never in this repository's tree
            subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"160000,{'5' * 40},{path}"],
                           check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=f", "-c", "user.email=f@example.invalid", "commit", "-qm",
                        "v", "--no-gpg-sign"], check=True)
        rev = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        for _ in range(16):
            (repo / ".github/ci-plan.json").write_text(json.dumps(cfg))
            buf = io.StringIO()
            out_json = repo / ".git" / "readers.json"
            try:
                with redirect_stdout(buf):
                    rc = E.main(["check", "--config", ".github/ci-plan.json", "--repo", str(repo), "--revision", rev,
                                 "--out-json", str(out_json)])
            except ValueError as err:
                return {"verdict": "REFUSE", "refusal": str(err)}
            fails = [line[5:] for line in buf.getvalue().splitlines() if line.startswith("FAIL ")]
            # Per path (root's ruling): a backstop hit plans that path FULL and fails nothing; its one declaration remedy
            # (map P to the mentioning package too) still narrows it back out, so it is applied like check's own.
            narrowed = False
            for line in buf.getvalue().splitlines():
                m = re.match(r"BACKSTOP (\S+) plans FULL: \S+ \(package (\S+)\) names \S+, but the mapping for \S+ selects", line)
                if m:
                    narrowed = bool(E_add(cfg, m.group(1), m.group(2))) or narrowed
            if rc == 0 and not narrowed:
                break
            progressed = narrowed
            for f in fails:
                for pattern, remedy in self.REMEDIES:
                    m = re.match(pattern, f)
                    if m:
                        progressed = bool(remedy(cfg, m)) or progressed
                        break
            if not progressed:
                return {"verdict": "STUCK", "fails": fails}
        pkgs = E.workspace_graph(repo, cfg)
        self.assertTrue(pkgs, "no packages: the judgment would be vacuous")
        sel = classify_paths([case["change"]], cfg, pkgs)
        if sel["error"] or sel["evidence"]["full_triggers"] or sel["evidence"]["unmapped"]:
            return {"verdict": "FULL"}
        # The backstop's consequence is per path (root's ruling, 2026-10-29): plan.py plans FULL for a changed path in
        # the bound assessment's backstop_full, exactly as it does for a full trigger.
        if case["change"] in (backstop_full(json.loads(out_json.read_text())) or []):
            return {"verdict": "FULL", "backstop": True}
        return {"verdict": "SELECT", "jobs": sorted(j for j, rule in cfg["jobs"].items()
                                                     if rule == "always" or rule_matches(rule, sel["affected"])[0])}



class RoundThreeVectorsTest(VectorHarness, unittest.TestCase):
    """Root's round 3 of #33: every fresh vector and correct-plan control, run by root's method and pinned EXACT
    (test_edges_round3_vectors.json)."""

    CASES = json.loads((Path(__file__).with_name("test_edges_round3_vectors.json")).read_text())

    def test_every_round3_vector_refuses_plans_full_or_selects_its_runner_exactly_as_pinned(self):
        for name, case in sorted(self.CASES["cases"].items()):
            with self.subTest(name):
                got = self.run_case(case)
                want = {k: case[k] for k in ("verdict", "jobs", "refusal", "backstop") if k in case}
                self.assertEqual(got, want, name)
                if case["kind"] == "drop-vector" and got["verdict"] == "SELECT" and case.get("must_run"):
                    self.assertIn(case["must_run"], got["jobs"], f"{name} drops its runner")

    def test_the_drop_vectors_cover_every_round3_class(self):
        kinds = {c["kind"] for c in self.CASES["cases"].values()}
        self.assertEqual(kinds, {"drop-vector", "correct-plan control"})
        names = sorted(self.CASES["cases"])
        for prefix in ("F10b", "F10 ", "F15", "F13b", "F12", "F01", "F02", "F03", "F04", "F05", "L1", "F09", "F08", "F11"):
            self.assertTrue(any(n.startswith(prefix) for n in names), prefix)


class RoundFourVectorsTest(VectorHarness, unittest.TestCase):
    """Root's R4 of #33 round 3 (lanes/root/reviews/dotgithub-33.md, head 70ed2e7): the reviewer's fresh vectors, pinned
    EXACT by the same method (test_edges_round4_vectors.json). Each drop-vector must REFUSE, plan FULL or select its
    runner: B1 (T1, T1b, T1c, a runner one hop or more out), B2 (T4, a gitlink), B3 (T3, T3b, a symlink alias or a
    symlink in a package), B4 (T2, an inert glob), and a runner that names only a directory (T10b-T10f; three precision
    controls: a package's own test/, a sibling path, bare words at the root). A residual is a spelling no recorded route or token sees (README,
    "Not closed"): it is pinned as the drop it is, so the README cannot claim more than the scan does."""

    CASES = json.loads((Path(__file__).with_name("test_edges_round4_vectors.json")).read_text())

    def test_every_round4_vector_refuses_plans_full_or_selects_its_runner_exactly_as_pinned(self):
        for name, case in sorted(self.CASES["cases"].items()):
            with self.subTest(name):
                got = self.run_case(case)
                self.assertEqual(got, {k: case[k] for k in ("verdict", "jobs", "refusal", "backstop") if k in case}, name)
                runs = got["verdict"] != "SELECT" or case["must_run"] in got["jobs"]
                self.assertEqual(runs, case["kind"] != "residual", f"{name}: {case['kind']}")

    def test_the_drop_vectors_cover_every_round4_blocker_and_the_readme_lists_every_residual(self):
        names = sorted(self.CASES["cases"])
        for prefix in ("T1 ", "T1b", "T1c", "T2 ", "T3 ", "T3b", "T4 ", "T10b", "T10c", "T10d", "T10e", "T10f"):
            self.assertTrue(any(n.startswith(prefix) and self.CASES["cases"][n]["kind"] == "drop-vector" for n in names),
                            prefix)
        readme = (Path(__file__).with_name("README.md")).read_text()
        for name, case in self.CASES["cases"].items():
            if case["kind"] == "residual":
                self.assertIn(case["residual"], readme, f"{name}: the README must list it")


class RulingsOf152Test(VectorHarness, unittest.TestCase):
    """1.5.2, root's rulings (a), (b), (c) and the nested-lockfile ruling (test_edges_152_rulings_vectors.json), pinned
    EXACT: each drop-vector refuses, plans FULL or selects its runner; each control selects exactly its jobs."""

    CASES = json.loads((Path(__file__).with_name("test_edges_152_rulings_vectors.json")).read_text())

    def test_every_ruling_vector_is_pinned_exactly(self):
        for name, case in sorted(self.CASES["cases"].items()):
            with self.subTest(name):
                got = self.run_case(case)
                self.assertEqual(got, {k: case[k] for k in ("verdict", "jobs", "refusal") if k in case}, name)
                if case["kind"] == "drop-vector" and got["verdict"] == "SELECT":
                    self.assertIn(case["must_run"], got["jobs"], f"{name} drops its runner")

    def test_each_ruling_has_vectors(self):
        names = sorted(self.CASES["cases"])
        for prefix in ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A7b", "A7c", "A7d", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B11",
                       "C1", "C2", "C3", "C4", "C5", "C6"):
            self.assertTrue(any(n.startswith(prefix + " ") for n in names), prefix)

def E_add(cfg, path, name):
    targets = cfg.setdefault("extra_edges", {}).setdefault(path, [])
    return E_list_add(targets, name)


def E_list_add(values, item):
    if item in values:
        return False
    values.append(item)
    return True


class PlannerReadFromSource(unittest.TestCase):
    """N2 (root's review of .github #52): edges.py compiles its sibling plan.py from SOURCE. A plan bytecode file planted
    in the action directory (the runner's shared action cache) never runs, and none is written there."""

    def _copy(self, tmp: str) -> Path:
        actions = Path(tmp) / "change-impact-plan"
        actions.mkdir()
        for name in ("edges.py", "plan.py"):
            shutil.copy(Path(__file__).with_name(name), actions / name)
        return actions

    def test_a_planted_plan_bytecode_never_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            actions = self._copy(tmp)
            src = actions / "plan.py"
            st = src.stat()
            # A pyc the import system would accept for this plan.py (its magic, the source's mtime and size), whose code
            # exits 77: if anything imports plan through the import system, the run exits 77.
            header = (importlib.util.MAGIC_NUMBER + (0).to_bytes(4, "little")
                      + (int(st.st_mtime) & 0xFFFFFFFF).to_bytes(4, "little") + (st.st_size & 0xFFFFFFFF).to_bytes(4, "little"))
            cache = actions / "__pycache__"
            cache.mkdir()
            planted = cache / f"plan.{sys.implementation.cache_tag}.pyc"
            planted.write_bytes(header + marshal.dumps(compile("import sys\nsys.exit(77)\n", str(src), "exec")))
            out = subprocess.run([sys.executable, "-I", str(actions / "edges.py"), "--help"], capture_output=True, text=True,
                                 timeout=120)
            self.assertNotEqual(out.returncode, 77, "the planted bytecode ran in place of plan.py")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(sorted(p.name for p in cache.iterdir()), [planted.name], "nothing else was written to the cache")

    def test_running_edges_writes_no_bytecode_into_the_action_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            actions = self._copy(tmp)
            out = subprocess.run([sys.executable, "-I", str(actions / "edges.py"), "--help"], capture_output=True, text=True,
                                 timeout=120)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual([p for p in actions.rglob("__pycache__")], [])


if __name__ == "__main__":
    unittest.main()
