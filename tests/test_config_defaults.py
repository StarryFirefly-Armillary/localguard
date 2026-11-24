"""Safe defaults: deterministic rules by default, model tiers opt-in."""
import json
from pathlib import Path

import localguard.engine as engine
from localguard.config import Config


def _config(tmp_path):
    return Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state')


def test_default_model_tier_is_rules(tmp_path):
    # No explicit config -> rules. Users without a GGUF must not trigger a
    # needless model startup / wait / warning.
    assert _config(tmp_path).model_tier == 'rules'
    # Config.load() with no config file must agree with the dataclass default.
    cfg = Config.load()
    assert cfg.model_tier == 'rules'


def test_explicit_8gb_config_is_preserved(tmp_path):
    p = tmp_path / 'cfg.json'
    p.write_text(json.dumps({'allowed_roots': [str(tmp_path)],
                             'data_dir': str(tmp_path / 'state'),
                             'model_tier': '8gb'}), encoding='utf-8')
    cfg = Config.load(str(p))
    assert cfg.model_tier == '8gb'


def test_explicit_4gb_config_is_preserved(tmp_path):
    cfg = Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state', model_tier='4gb')
    assert cfg.model_tier == '4gb'


def test_model_triage_default_unchanged():
    # Changing the tier default must not also change triage's default: users
    # who explicitly opt into a model tier still get advisory triage.
    src = Path(engine.__file__).read_text(encoding='utf-8')
    assert "args.get('model_triage', True)" in src
