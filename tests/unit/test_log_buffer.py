from personal_linux_mcp.jobs.store import JobStore


def test_job_store_survives_new_instance(tmp_path):
    row = {
        "job_id": "j1",
        "server": "a",
        "cwd": "/work",
        "remote_dir": "/work/jobs/j1",
        "status": "running",
        "exit_code": None,
        "remote_pid": 10,
        "start_ticks": 20,
        "started_at": "2026-01-01T00:00:00+00:00",
        "ended_at": None,
        "termination_requested": 0,
        "message": None,
    }
    JobStore(str(tmp_path)).insert(row)
    reopened = JobStore(str(tmp_path))
    assert reopened.get("j1")["remote_dir"] == "/work/jobs/j1"
    reopened.update("j1", status="completed", exit_code=0)
    assert JobStore(str(tmp_path)).get("j1")["status"] == "completed"
