"""Optional UI regression: scan results must survive interactive reruns."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

from cryptograph.utils import project_path


def test_scan_filter_and_baseline_labels_survive_reruns(tmp_path: Path) -> None:
    source = tmp_path / "example.py"
    source.write_text("import hashlib\nhashlib.md5(b'example')\n", encoding="utf-8")
    app = AppTest.from_file(str(project_path("viewer", "scanner.py")), default_timeout=60).run()
    app.text_input[0].set_value(str(tmp_path))
    next(button for button in app.button if button.label == "Scan").click().run()
    assert not app.exception
    assert any(metric.label == "Primary assets" and int(metric.value) == 1 for metric in app.metric)

    risk_filter = next(select for select in app.selectbox if select.label == "Risk filter")
    risk_filter.set_value(risk_filter.options[-1]).run()
    assert not app.exception and app.metric
    next(button for button in app.button if button.label == "Generate baseline labels").click().run()
    assert not app.exception
    assert (Path(app.session_state["scan"]["out_dir"]) / "baseline.jsonl").is_file()
    app.run()
    assert not app.exception and app.metric
