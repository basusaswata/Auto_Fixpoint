from loader import load_config


def test_load():
    assert load_config("a: 1") == {"a": 1}
