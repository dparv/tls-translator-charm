import pathlib
import sys


def pytest_configure(config):
    project_root = pathlib.Path(__file__).resolve().parents[1]
    src_path = project_root / "src"
    sys.path.insert(0, str(src_path))
