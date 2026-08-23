import argparse
import os
import signal
import sqlite3
import time
from datetime import datetime, time as wall_time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo


DATA = Path(os.environ.get("UEM_DATA_DIR", "/data"))
DB = DATA / "metadata.db"
TIME_ZONE = ZoneInfo(os.environ.get("UEM_CLEANUP_TIMEZONE", "Europe/Zurich"))
RUN_AT = wall_time(23, 59)
stop_requested = False


def request_stop(_signum, _frame):
    global stop_requested
    stop_requested = True


def cleanup_for(local_date):
    end_local = datetime.combine(local_date + timedelta(days=1), wall_time.min, TIME_ZONE)
    end_utc = end_local.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    deleted = 0
    with sqlite3.connect(DB, timeout=30) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT file_id, object_key FROM files WHERE created_at < ?",
            (end_utc,),
        ).fetchall()
        for row in rows:
            (DATA / row["object_key"]).unlink(missing_ok=True)
            connection.execute("DELETE FROM files WHERE file_id=?", (row["file_id"],))
            deleted += 1
        connection.execute("DELETE FROM oidc_sessions WHERE created_at < datetime('now', '-1 day')")
    for owner_dir in (DATA / "objects").glob("*"):
        if owner_dir.is_dir():
            try:
                owner_dir.rmdir()
            except OSError:
                pass
    print(f"cleanup date={local_date.isoformat()} timezone={TIME_ZONE.key} deleted={deleted}", flush=True)
    return deleted


def wait_for_database():
    while not stop_requested:
        if DB.exists():
            try:
                with sqlite3.connect(DB, timeout=5) as connection:
                    connection.execute("SELECT 1 FROM files LIMIT 1")
                return True
            except sqlite3.Error:
                pass
        time.sleep(2)
    return False


def run_scheduler():
    if not wait_for_database():
        return
    while not stop_requested:
        now = datetime.now(TIME_ZONE)
        target = datetime.combine(now.date(), RUN_AT, TIME_ZONE)
        if now >= target:
            target += timedelta(days=1)
        print(f"next cleanup={target.isoformat()}", flush=True)
        while not stop_requested:
            remaining = (target - datetime.now(TIME_ZONE)).total_seconds()
            if remaining <= 0:
                break
            time.sleep(min(remaining, 30))
        if not stop_requested:
            cleanup_date = target.date()
            cleanup_for(cleanup_date)
            midnight = datetime.combine(cleanup_date + timedelta(days=1), wall_time.min, TIME_ZONE)
            while not stop_requested:
                remaining = (midnight - datetime.now(TIME_ZONE)).total_seconds()
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 30))
            if not stop_requested:
                # Catch uploads made during the final minute after the 23:59 sweep.
                cleanup_for(cleanup_date)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-once", action="store_true", help="Run cleanup immediately for the current local day")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    if args.run_once:
        if wait_for_database():
            cleanup_for(datetime.now(TIME_ZONE).date())
    else:
        run_scheduler()
