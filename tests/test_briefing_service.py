from models.database import Base, ScanDB, ScanBriefingDB, SessionLocal, engine
from services import briefing_service


def _scan():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        scan = ScanDB(target="example.com", scanners_used=[], status="completed")
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


def test_get_briefing_reports_none_before_generation():
    assert briefing_service.get_briefing(987654)["status"] == "none"


def test_generation_stores_ready_payload(monkeypatch):
    scan_id = _scan()

    class FakeEngine:
        def explain_scan(self, *args, **kwargs):
            return {"explanation": "All clear.", "finding_count": 0, "error": None}

    import services.rag_engine as rag_module

    monkeypatch.setattr(rag_module, "rag_engine", FakeEngine())
    briefing_service.generate_briefing(scan_id)

    stored = briefing_service.get_briefing(scan_id)
    assert stored["status"] == "ready"
    assert stored["explanation"] == "All clear."


def test_generation_failure_is_recorded(monkeypatch):
    scan_id = _scan()

    class BrokenEngine:
        def explain_scan(self, *args, **kwargs):
            raise RuntimeError("provider down")

    import services.rag_engine as rag_module

    monkeypatch.setattr(rag_module, "rag_engine", BrokenEngine())
    briefing_service.generate_briefing(scan_id)

    stored = briefing_service.get_briefing(scan_id)
    assert stored["status"] == "failed"
    assert "provider down" in stored["error"]
