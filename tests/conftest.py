import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "backend")):
    if path not in sys.path:
        sys.path.insert(0, path)

# Point the suite at a throwaway database before config is imported. Without
# this, tests that insert rows wrote them into backend/data/vulndetect.db and
# every run left empty "example.com" scans in the user's real scan history.
_TEST_DB_DIR = tempfile.mkdtemp(prefix="vulndetect-tests-")
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_TEST_DB_DIR, "test.db").replace("\\", "/")

import pytest  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def _test_schema():
    """Create the schema in the throwaway database once per run."""
    from models.database import init_db

    init_db()
    yield
