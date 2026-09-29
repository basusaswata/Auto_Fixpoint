from app import app


def test_app_loads():
    assert app.name == "app"
