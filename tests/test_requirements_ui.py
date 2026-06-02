from pathlib import Path


DASHBOARD_TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "index.html"


def test_dashboard_has_requirements_list_and_install_button():
    html = DASHBOARD_TEMPLATE.read_text(encoding="utf-8")

    assert 'id="requirements-status"' in html
    assert 'id="requirements-install-log"' in html
    assert "loadRequirementsStatus()" in html
    assert "installMissingRequirements()" in html
    assert "/api/requirements/status" in html
    assert "/api/requirements/install" in html

