import textwrap

import pytest

from scanner.config import ConfigError, load_config

ROOT_CONFIG = "config.yaml"


def write(tmp_path, body):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def test_loads_shipped_config():
    cfg = load_config(ROOT_CONFIG)
    assert cfg.rules
    assert all(r.regex is not None for r in cfg.rules)
    assert cfg.severity_weights["critical"] > cfg.severity_weights["low"]


def test_missing_field_fails_loudly(tmp_path):
    p = write(tmp_path, """
        settings: {}
        rules:
          - id: broken
            severity: high
            pattern: 'x'
    """)
    with pytest.raises(ConfigError) as e:
        load_config(p)
    assert "category" in str(e.value) and "description" in str(e.value)


def test_bad_regex_fails_loudly(tmp_path):
    p = write(tmp_path, """
        settings: {}
        rules:
          - id: bad_regex
            category: x
            severity: high
            pattern: '([unclosed'
            description: 'nope'
    """)
    with pytest.raises(ConfigError) as e:
        load_config(p)
    assert "invalid regex" in str(e.value)


def test_bad_severity_fails(tmp_path):
    p = write(tmp_path, """
        settings: {}
        rules:
          - id: bad_sev
            category: x
            severity: catastrophic
            pattern: 'x'
            description: 'nope'
    """)
    with pytest.raises(ConfigError):
        load_config(p)


def test_duplicate_ids_fail(tmp_path):
    p = write(tmp_path, """
        settings: {}
        rules:
          - id: dup
            category: x
            severity: low
            pattern: 'a'
            description: 'one'
          - id: dup
            category: x
            severity: low
            pattern: 'b'
            description: 'two'
    """)
    with pytest.raises(ConfigError) as e:
        load_config(p)
    assert "duplicate" in str(e.value)
