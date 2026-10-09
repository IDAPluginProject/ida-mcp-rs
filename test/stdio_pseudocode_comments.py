"""Exercise exact native pseudocode comment placement and persistence."""

import argparse
import platform
import re
import shutil
import tempfile
from pathlib import Path

from stdio_lvars import Client, decode, rejected


def check_shared_slot(client):
    """One `stp xzr, xzr` renders as two statements sharing one comment slot.

    Hex-Rays prints a shared slot's comment once, on the first such line, so
    only that line is listed and a comment set through it renders there.
    """
    function = decode(client.call("resolve_function", {"name": "clear_pair"}))
    target = {"target_name": function["name"]}
    stores = [line.strip() for line in
              decode(client.call("decompile", {"address": function["address"]})).splitlines()
              if line.strip().endswith("= 0;")]
    assert len(stores) == 2, stores
    rows = decode(client.call("list_pseudocode_comments", target))["locations"]
    listed = [row for row in rows if row["text"].strip() in stores]
    assert [row["text"].strip() for row in listed] == stores[:1], rows
    decode(client.call("set_pseudocode_comment", {
        **target, "comment_locator": listed[0]["locator"], "comment": "issue62 shared"}))
    pseudocode = decode(client.call("decompile", {"address": function["address"]}))
    commented = [line.strip() for line in pseudocode.splitlines() if "issue62 shared" in line]
    assert len(commented) == 1 and commented[0].startswith(stores[0]), pseudocode


def exercise(binary, fixture, workspace):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-pseudocode-comments-") as temporary:
        directory = Path(temporary)
        database = directory / "mini.i64"
        shutil.copy2(fixture, database)
        args = ("--workspace", "--workspace-max-workers", "1") if workspace else ()
        client = Client(binary, directory, args)
        try:
            client.open(database)
            function = decode(client.call("resolve_function", {"name": "interesting_function"}))
            target = {"target_name": function["name"]}

            def locations(selector=None):
                listing = decode(client.call("list_pseudocode_comments",
                                             {**(selector or target), "limit": 1000}))
                assert listing["target"]["address"] == function["address"], listing
                assert len(listing["locations"]) == listing["total"], listing
                return listing["locations"]

            initial = locations()
            by_text = {row["text"].strip(): row for row in initial}
            alternative = by_text["else"]
            condition = next(row for row in initial if row["text"].lstrip().startswith("if ("))
            assert alternative["address"] == condition["address"], initial
            assert alternative["locator"] != condition["locator"], initial
            assert len({row["locator"] for row in initial}) == len(initial), initial
            assert locations({"address": alternative["address"]}) == initial
            page = decode(client.call("list_pseudocode_comments", {**target, "limit": 1}))
            assert page["locations"] == initial[:1] and page["next_offset"] == 1, page

            def write(location, text, **overrides):
                return client.call("set_pseudocode_comment", {
                    **target, "comment_locator": location["locator"], "comment": text,
                    **overrides,
                })

            other = decode(client.call("resolve_function", {"name": "helper_mix"}))
            rejected(write(alternative, "wrong function", target_name=other["name"]), "stale")
            rejected(write(alternative, "stale", comment_locator=alternative["locator"] + "0"), "stale")
            assert locations() == initial

            if platform.machine().lower() in ("arm64", "aarch64"):
                check_shared_slot(client)

            decode(write(condition, "issue62 condition"))
            decode(write(alternative, "issue62 old alternative\nsecond line"))
            assert next(row for row in locations() if row["locator"] == alternative["locator"])["comment"] == "issue62 old alternative\nsecond line"
            changed = decode(write(alternative, "issue62 alternative"))
            assert not changed["deleted"] and changed["target"]["address"] == function["address"], changed
            assert changed["comment_locator"] == alternative["locator"], changed
            decode(client.call("save_idb", {}))
            client.close_database()
            client.open(database)
            rows = {row["locator"]: row for row in locations()}
            assert rows[condition["locator"]]["comment"] == "issue62 condition", rows
            assert rows[alternative["locator"]]["comment"] == "issue62 alternative", rows
            pseudocode = decode(client.call("decompile", {"address": function["address"]}))
            assert re.search(r"if \([^\n]+// issue62 condition", pseudocode), pseudocode
            assert re.search(r"\belse\s+// issue62 alternative", pseudocode), pseudocode
            assert "issue62 old alternative" not in pseudocode

            deleted = decode(write(alternative, ""))
            assert deleted["deleted"], deleted
            decode(client.call("save_idb", {}))
            client.close_database()
            client.open(database)
            rows = {row["locator"]: row for row in locations()}
            assert rows[alternative["locator"]]["comment"] == "", rows
            assert rows[condition["locator"]]["comment"] == "issue62 condition", rows
            pseudocode = decode(client.call("decompile", {"address": function["address"]}))
            assert "issue62 alternative" not in pseudocode, pseudocode
            client.close_database()
        except BaseException:
            print(client.log_path.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            client.finish()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    args = parser.parse_args()
    for workspace in (False, True):
        exercise(args.binary.resolve(), args.fixture.resolve(), workspace)
        print(f"Pseudocode comments passed ({'workspace' if workspace else 'stdio'})")
