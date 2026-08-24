import argparse
import os
import signal
import time
from datetime import datetime, time as wall_time, timedelta, timezone
from zoneinfo import ZoneInfo

import boto3
import psycopg
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from psycopg.rows import dict_row


DATABASE_URL = os.environ["UEM_DATABASE_URL"]
S3_BUCKET = os.environ["UEM_S3_BUCKET"]
S3 = boto3.client(
    "s3",
    endpoint_url=os.environ["UEM_S3_ENDPOINT"],
    aws_access_key_id=os.environ["UEM_S3_ACCESS_KEY"],
    aws_secret_access_key=os.environ["UEM_S3_SECRET_KEY"],
    region_name=os.environ["UEM_S3_REGION"],
    config=Config(s3={"addressing_style": "path"}),
)
TIME_ZONE = ZoneInfo(os.environ.get("UEM_CLEANUP_TIMEZONE", "Europe/Zurich"))
RUN_AT = wall_time(23, 59)
stop_requested = False


def request_stop(_signum, _frame):
    global stop_requested
    stop_requested = True


def db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def cleanup_for(local_date):
    end_local = datetime.combine(local_date + timedelta(days=1), wall_time.min, TIME_ZONE)
    end_utc = end_local.astimezone(timezone.utc)
    deleted = 0
    with db() as connection:
        rows = connection.execute(
            "SELECT file_id, object_key FROM files WHERE created_at < %s ORDER BY created_at",
            (end_utc,),
        ).fetchall()
        for row in rows:
            try:
                S3.delete_object(Bucket=S3_BUCKET, Key=row["object_key"])
            except (BotoCoreError, ClientError) as error:
                print(f"cleanup object={row['object_key']} error={error.__class__.__name__}", flush=True)
                continue
            connection.execute("DELETE FROM files WHERE file_id=%s", (row["file_id"],))
            deleted += 1
        connection.execute("DELETE FROM oidc_sessions WHERE created_at < NOW() - INTERVAL '1 day'")
    print(f"cleanup date={local_date.isoformat()} timezone={TIME_ZONE.key} deleted={deleted}", flush=True)
    return deleted


def wait_for_storage():
    while not stop_requested:
        try:
            S3.head_bucket(Bucket=S3_BUCKET)
            with db() as connection:
                connection.execute("SELECT 1 FROM files LIMIT 1")
            return True
        except (psycopg.Error, BotoCoreError, ClientError):
            time.sleep(2)
    return False


def run_scheduler():
    if not wait_for_storage():
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
                cleanup_for(cleanup_date)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-once", action="store_true", help="Run cleanup immediately for the current local day")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    if args.run_once:
        if wait_for_storage():
            cleanup_for(datetime.now(TIME_ZONE).date())
    else:
        run_scheduler()
