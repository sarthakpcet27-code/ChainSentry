"""
Unit tests for Transitive Lockfile Parser.
"""

from backend.parsers.lockfiles import parse_package_lock_json


def test_parse_package_lock_v2(tmp_path):
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(
        """
{
  "name": "sample-project",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "dependencies": {
        "express": "^4.18.2"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "qs": "6.11.0"
      }
    },
    "node_modules/qs": {
      "version": "6.11.0"
    }
  }
}
        """,
        encoding="utf-8",
    )

    deps = parse_package_lock_json(lock_file)
    assert len(deps) == 2

    by_name = {d["package"]: d for d in deps}
    assert "express" in by_name
    assert "qs" in by_name

    assert by_name["express"]["direct"] is True
    assert by_name["express"]["depth"] == 1

    assert by_name["qs"]["direct"] is False
    assert by_name["qs"]["depth"] >= 2
    assert "express" in by_name["qs"]["parent_packages"]
