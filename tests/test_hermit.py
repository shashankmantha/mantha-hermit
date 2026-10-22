import tempfile
import unittest
from pathlib import Path

from hermit import llm
from hermit.classify import Category, Signal, load_categories, propose_severity, score, _term_regex
from hermit.features import extract
from hermit.parse import Source, parse_file, subset_text
from hermit.store import Store

RULES = r'''
import "pe"
global private rule SizeLimit { condition: filesize < 50MB }
private rule IsPE { condition: uint16(0) == 0x5A4D }
rule MAL_Lumma_Stealer_Test : stealer {
  meta: description = "Lumma stealer delivered as a fake game crack" score = 80
  strings: $a = "\\Local State" $b = "steam_api64.dll"
  condition: IsPE and all of them
}
rule WEBSHELL_PHP_Test { strings: $a = "<?php eval($_POST" condition: $a }
rule LOKI_Name_Test { condition: filename == "evil.exe" }
rule Elf_Miner_Test { meta: description = "Linux miner" strings: $a = "stratum+tcp://" condition: uint32(0) == 0x464c457f and $a }
'''


def load(text=RULES):
    d = Path(tempfile.mkdtemp())
    (d / "t.yar").write_text(text)
    return parse_file(Source("test", d), d / "t.yar", "t.yar", None)


class ParseTests(unittest.TestCase):
    def test_parse_and_compile(self):
        rf = load()
        names = {r.name: r for r in rf.rules}
        self.assertTrue(all(r.compile_ok for r in rf.rules), [r.compile_error for r in rf.rules])
        self.assertEqual(names["MAL_Lumma_Stealer_Test"].deps, ["IsPE"])
        self.assertEqual(names["LOKI_Name_Test"].externals, ["filename"])

    def test_subset_keeps_dependencies_and_globals(self):
        rf = load()
        lumma = [r for r in rf.rules if r.name == "MAL_Lumma_Stealer_Test"]
        text = subset_text(rf, lumma)
        for needed in ('import "pe"', "rule SizeLimit", "rule IsPE", "rule MAL_Lumma"):
            self.assertIn(needed, text)
        self.assertNotIn("WEBSHELL", text)

    def test_broken_rule_is_isolated(self):
        rf = load(RULES + '\nrule Broken { condition: unknown_module.x }\n')
        bad = [r for r in rf.rules if not r.compile_ok]
        self.assertEqual([r.name for r in bad], ["Broken"])


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.rules = {r.name: r for r in load().rules}

    def test_targets(self):
        self.assertEqual(extract(self.rules["Elf_Miner_Test"]).targets, ["elf"])
        self.assertIn("webshell", extract(self.rules["WEBSHELL_PHP_Test"]).targets)
        self.assertEqual(extract(self.rules["LOKI_Name_Test"]).targets, ["any"])

    def test_word_boundaries(self):
        self.assertTrue(_term_regex("rat").search("remote rat tool"))
        self.assertFalse(_term_regex("rat").search("pirate"))
        self.assertTrue(_term_regex("pirat*").search("pirated copy"))
        self.assertTrue(_term_regex("steam api").search("steam_api"))


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.rules = {r.name: r for r in load().rules}
        self.cat = Category("games", "game stuff", targets_allow=["pe", "elf", "script"],
                            targets_deny=["webshell"],
                            signals=[Signal(4, ["name", "tags", "description"], ["game"]),
                                     Signal(3, ["strings"], ["steam_api"])])

    def test_include_and_reasons(self):
        r = self.rules["MAL_Lumma_Stealer_Test"]
        d = score(r, extract(r), self.cat)
        self.assertEqual((d.score, d.band), (7, "include"))
        self.assertEqual(len(d.reasons), 2)

    def test_not_applicable(self):
        r = self.rules["WEBSHELL_PHP_Test"]
        self.assertEqual(score(r, extract(r), self.cat).band, "not_applicable")

    def test_severity(self):
        r = self.rules["MAL_Lumma_Stealer_Test"]
        self.assertEqual(propose_severity(r, self.cat)[0], "threat")
        self.cat.severity_cap = "info"
        self.assertEqual(propose_severity(r, self.cat)[0], "info")

    def test_shipped_config_loads(self):
        import tomllib
        root = Path(__file__).resolve().parent.parent / "config"
        cats = load_categories(tomllib.loads((root / "categories.toml").read_text()))
        self.assertIn("core-threats", cats)
        r = self.rules["MAL_Lumma_Stealer_Test"]
        self.assertEqual(score(r, extract(r), cats["cracked-software"]).band, "include")


class FakeClient:
    model = "fake"

    def __init__(self, reply):
        self.reply = reply

    def chat_json(self, system, user):
        return self.reply


class LLMTests(unittest.TestCase):
    def test_judge_validates(self):
        r = load().rules[2]
        cat = Category("games", "d")
        store = Store(Path(tempfile.mkdtemp()) / "s.db")
        out = llm.judge(FakeClient({"decisions": {"games": {"applies": True, "confidence": 7},
                                                  "other": {"applies": True}}, "reason": "x" * 999}),
                        store, r, extract(r), [cat])
        self.assertEqual(out["decisions"], {"games": (True, 1.0)})
        self.assertLessEqual(len(out["reason"]), 200)

    def test_plan_is_sanitised(self):
        plan = llm.plan_query(FakeClient({"slug": "A B!", "name_terms": ["ok", "x;rm -rf /", 5],
                                          "targets_allow": ["pe", "nope"]}), "q")
        self.assertEqual(plan["slug"], "a-b")
        self.assertEqual(plan["name_terms"], ["ok"])
        self.assertEqual(plan["targets_allow"], ["pe"])


class NoveltyTests(unittest.TestCase):
    def test_new_changed_seen(self):
        store = Store(Path(tempfile.mkdtemp()) / "s.db")
        rules = load().rules
        self.assertEqual(set(store.novelty(rules).values()), {"new"})
        store.record_run("t", rules)
        self.assertEqual(set(store.novelty(rules).values()), {"seen"})
        rules[2].sha256 = "different"
        self.assertEqual(store.novelty(rules)[rules[2].key], "changed")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- ask / live packs

from datetime import date

from hermit import intent
from hermit.livepacks import LivePack, make_entry

PACKS = {"games": "game rules", "cracked-software": "cracks", "core-threats": "malware"}
ALIASES = {"games": ["video games", "game"], "cracked-software": ["cracked software", "cracks"],
           "core-threats": ["malware"]}
TODAY = date(2026, 10, 20)


class IntentTests(unittest.TestCase):
    def p(self, text):
        return intent.parse(text, PACKS, ALIASES, TODAY)

    def test_add_new_games(self):
        it = self.p("update rule list to include all new rules related to video games")
        self.assertEqual((it["action"], it["selection"], it["target_pack"], it["topic_pack"]),
                         ("add", "new", "games", "games"))

    def test_remove_named(self):
        it = self.p("remove MAL_Foo_Test from games")
        self.assertEqual((it["action"], it["target_pack"], it["rule_names"]), ("remove", "games", ["MAL_Foo_Test"]))

    def test_report_since_month(self):
        it = self.p("what changed in cracked software this month?")
        self.assertEqual((it["action"], it["since"], it["target_pack"]), ("report", "2026-10-01", "cracked-software"))

    def test_unknown_pack(self):
        with self.assertRaises(llm.IntentError):
            self.p("update stuff please")

    def test_model_output_is_validated(self):
        for bad in ({"action": "delete_everything", "target_pack": "games"},
                    {"action": "add", "target_pack": "../../etc", "topic_pack": "games"},
                    {"action": "add", "target_pack": "games", "topic_pack": "nope"},
                    {"action": "add", "target_pack": "brand-new"},
                    {"action": "remove", "target_pack": "brand-new", "rule_names": ["X_Y"]},
                    {"action": "add", "selection": "since", "since": "yesterday", "target_pack": "games",
                     "topic_pack": "games"}):
            with self.assertRaises(llm.IntentError, msg=bad):
                llm.validate_intent(bad, PACKS)


class IntentDefaultTests(unittest.TestCase):
    def test_add_without_topic_uses_target_pack(self):
        # what qwen2.5:7b-instruct actually returned for "...new rules related to video games"
        raw = {"action": "add", "selection": "new", "since": None, "topic_pack": None,
               "topic_text": None, "target_pack": "games", "rule_names": []}
        self.assertEqual(llm.validate_intent(raw, PACKS)["topic_pack"], "games")

    def test_remove_without_topic_still_rejected(self):
        with self.assertRaises(llm.IntentError):
            llm.validate_intent({"action": "remove", "target_pack": "games"}, PACKS)


class LivePackTests(unittest.TestCase):
    def test_commit_compile_rollback(self):
        rf = load()
        root = Path(tempfile.mkdtemp())
        pack = LivePack.open(root, "games")
        lumma = next(r for r in rf.rules if r.name == "MAL_Lumma_Stealer_Test")
        e = make_entry(lumma, rf, proposed_severity="threat", severity_reason="t", decided_by="rules",
                       reasons=[], llm_reason=None, uncertain=False, probation_days=14, version=1,
                       upstream=(None, None))
        self.assertEqual(e["severity"], "info")  # probation
        pack.entries[e["key"]] = e
        self.assertEqual(pack.commit("first", ["added"], {lumma.key: lumma.sha256}), [])
        self.assertTrue((root / "games" / "pack.yarx").is_file())
        text = next((root / "games" / "rules").rglob("*.yar")).read_text()
        self.assertIn("rule IsPE", text)       # dependency carried along
        self.assertIn("rule SizeLimit", text)  # global rule carried along
        reopened = LivePack.open(root, "games")
        self.assertFalse(reopened.is_new_to_pack(lumma))
        reopened.rollback(0)
        self.assertEqual(reopened.entries, {})
        self.assertTrue(reopened.is_new_to_pack(lumma))
        self.assertEqual(reopened.version, 2)
        reopened.rollback(1)
        self.assertIn(lumma.key, reopened.entries)


class ToolSeverityTests(unittest.TestCase):
    def test_forge_tool_rule_is_info_despite_score(self):
        rf = load('rule SEKOIA_Tool_Cheat_Engine { meta: score = 75 strings: $a = "x" condition: $a }')
        sev, why = propose_severity(rf.rules[0], Category("games", "d"))
        self.assertEqual(sev, "info", why)


# ---------------------------------------------------------------- bundle contract v1

import json as _json
import tarfile as _tarfile
from types import SimpleNamespace

from hermit import bundle, contract, signing


def _fake_cfg(root: Path, **bundle_opts):
    main = {"bundle": {"require_licence": False, "include_compiled": True, "yara_x_version": "",
                       "public_key": str(root / "k.pub"), "secret_key": str(root / "k.key"), **bundle_opts},
            "automation": {}}
    return SimpleNamespace(main=main, packs_dir=root / "packs", state_db=root / "state" / "s.db", root=root)


def _live_pack(root: Path, licence: str | None = "https://example.org/LICENSE") -> LivePack:
    rf = load()
    pack = LivePack.open(root / "packs", "games", kind="recognition", description="d", editions=["standard"])
    for r in rf.rules:
        if r.name in ("MAL_Lumma_Stealer_Test", "Elf_Miner_Test", "LOKI_Name_Test"):
            e = make_entry(r, rf, proposed_severity="threat", severity_reason="t", decided_by="rules",
                           reasons=[], llm_reason=None, uncertain=False, probation_days=0, version=1,
                           upstream=("someone/rules", licence))
            pack.entries[e["key"]] = e
    assert pack.commit("first", [], {}) == []
    return pack


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.pack = _live_pack(self.root)
        self.cfg = _fake_cfg(self.root)

    def test_live_pack_is_valid_contract(self):
        s = contract.validate_pack(self.root / "packs" / "games", allow_state=True)
        self.assertEqual(s["rules"], 3)
        meta = _json.loads((self.root / "packs" / "games" / "pack.json").read_text())
        self.assertEqual(meta["externals"], ["filename"])
        self.assertTrue(all(r["file"] == f"rules/{r['namespace']}.yar" for r in meta["rules"]))

    def test_export_validates_and_hashes(self):
        out = self.root / "b"
        built = bundle.build_tree(self.cfg, out, lambda m: None)
        self.assertEqual(contract.validate_bundle(out)["packs"][0]["rules"], 3)
        self.assertRegex(built["manifest"]["bundle_version"], r"^\d{4}\.\d+\.\d+\.1$")
        (out / "packs" / "games" / "rules" / "extra.yar").write_text("rule x { condition: true }")
        with self.assertRaises(contract.ContractError):
            contract.validate_bundle(out)

    def test_validator_rejects_bad_files(self):
        out = self.root / "b"
        bundle.build_tree(self.cfg, out, lambda m: None)
        pdir = out / "packs" / "games"
        good = (pdir / "severities.json").read_text()
        for mutate in (lambda d: d["severities"].update({"x:y": "threat"}),
                       lambda d: d["severities"].update({k: "critical" for k in list(d["severities"])[:1]}),
                       lambda d: d.update({"extra": 1}),
                       lambda d: d["probation"].update({k: "2026-12-01" for k in list(d["severities"])[:1]})):
            d = _json.loads(good)
            mutate(d)
            (pdir / "severities.json").write_text(_json.dumps(d))
            with self.assertRaises(contract.ContractError, msg=str(d)[:80]):
                contract.validate_pack(pdir)
        (pdir / "severities.json").write_text(good)
        contract.validate_pack(pdir)

    def test_licence_filter(self):
        root = Path(tempfile.mkdtemp())
        _live_pack(root, licence=None)
        with self.assertRaises(bundle.BundleError):
            bundle.build_tree(_fake_cfg(root, require_licence=True), root / "b", lambda m: None)
        built = bundle.build_tree(_fake_cfg(root, require_licence=False), root / "b2", lambda m: None)
        self.assertEqual(built["packs"][0]["rules"], 3)

    def test_sign_tarball_verify_and_tamper(self):
        signing.generate_keypair(self.root / "k.pub", self.root / "k.key")
        tree = self.root / "tree"
        built = bundle.build_tree(self.cfg, tree, lambda m: None)
        v = built["manifest"]["bundle_version"]
        tb = self.root / f"mantha-packs-{v}.tar.gz"
        bundle.make_tarball(tree, tb)
        first = contract.sha256_file(tb)
        bundle.make_tarball(tree, self.root / "again.tar.gz")
        self.assertEqual(first, contract.sha256_file(self.root / "again.tar.gz"))  # reproducible
        signing.sign_file(tb, self.root / "k.key", f"mantha-packs {v}")
        pub = (self.root / "k.pub").read_text()
        self.assertEqual(bundle.verify_bundle(tb, pub)["bundle_version"], v)
        data = bytearray(tb.read_bytes())
        data[len(data) // 2] ^= 0x01
        tb.write_bytes(bytes(data))
        with self.assertRaises(signing.SignatureError):
            bundle.verify_bundle(tb, pub)

    def test_safe_extract_rejects_escape(self):
        tb = self.root / "evil.tar.gz"
        with _tarfile.open(tb, "w:gz") as t:
            info = _tarfile.TarInfo("../escape")
            info.size = 1
            import io
            t.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(bundle.BundleError):
            bundle.safe_extract(tb, self.root / "x")
        self.assertFalse((self.root / "escape").exists())

    def test_changes_text(self):
        self.assertIn("+1", bundle.describe_changes({"g": {"a": "info"}}, {"g": {"a": "info", "b": "threat"}}))
        self.assertIn("1 severity change", bundle.describe_changes({"g": {"a": "info"}}, {"g": {"a": "threat"}}))
