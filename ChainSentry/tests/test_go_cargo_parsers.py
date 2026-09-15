"""
Tests for Go go.mod and Cargo Cargo.toml static manifest parsers.
"""

from backend.parsers.go_mod import parse_go_mod_content
from backend.parsers.cargo_toml import parse_cargo_toml_content
from backend.models.enums import Ecosystem


def test_parse_go_mod_content():
    content = """
    module demo

    go 1.20

    require (
        github.com/example/unreleased-lib v0.0.0-20230101000000-main
        github.com/gin-gonic/gin v1.9.1
    )
    """
    deps = parse_go_mod_content(content, source_path="go/go.mod")
    assert len(deps) == 2
    assert deps[0].package_name == "github.com/example/unreleased-lib"
    assert deps[0].version == "v0.0.0-20230101000000-main"
    assert deps[0].ecosystem == Ecosystem.GO
    assert deps[1].package_name == "github.com/gin-gonic/gin"
    assert deps[1].version == "v1.9.1"


def test_parse_cargo_toml_content():
    content = """
    [package]
    name = "demo"
    version = "0.1.0"

    [dependencies]
    unhashed-git-pkg = { git = "https://github.com/example/unhashed-git-pkg.git" }
    serde = "1.0.195"
    """
    deps = parse_cargo_toml_content(content, source_path="rust/Cargo.toml")
    assert len(deps) == 2
    assert deps[0].package_name == "unhashed-git-pkg"
    assert deps[0].metadata.get("is_git_dependency") is True
    assert deps[0].ecosystem == Ecosystem.CARGO
    assert deps[1].package_name == "serde"
    assert deps[1].version == "1.0.195"
