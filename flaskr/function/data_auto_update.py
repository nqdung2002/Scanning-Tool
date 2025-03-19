import os
import json
import datetime
import time
import logging
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR

from .data_download import modified_recent_pull, complete_pull
from .cve_scan import indexing_modified_recent_cve, indexing_full_cve
from .cpe_scan import indexing_cpe
from flaskr.monitor import auto_scan
from flask import current_app

# Múi giờ Haloi
gmt7 = datetime.timezone(datetime.timedelta(hours=7))

# Biến toàn cục để lưu scheduler
scheduler = None

# --- Cấu hình logger riêng cho module này ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.propagate = False  # Không chuyển log lên root

# Tạo thư mục log nếu chưa có
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../log'))
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)


if not logger.hasHandlers():
    # FileHandler: ghi log ra file update.log
    file_handler = logging.FileHandler(os.path.join(LOG_DIR, "update.log"), encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter("%(asctime)s - %(message)s")
    file_handler.setFormatter(file_formatter)

    # StreamHandler: ghi log ra terminal
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_formatter = logging.Formatter("%(asctime)s - %(message)s")
    stream_handler.setFormatter(stream_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

# Cấu hình file job store bên ngoài 
JOB_STORE_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src/last_update.json"))

def load_last_update():
    try:
        with open(JOB_STORE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return {}

def save_last_update(data):
    with open(JOB_STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)

def next_run_time_cron(hour, minute):
    now = datetime.datetime.now(gmt7)
    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if next_run <= now:
        next_run += datetime.timedelta(days=1)
    return next_run

def next_run_time_modified_recent_cron():
    now = datetime.datetime.now(gmt7)
    # Danh sách giờ cho phép (không bao gồm 2)
    allowed_hours = [0, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]
    candidate = None
    for hour in allowed_hours:
        candidate_time = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if candidate_time > now:
            candidate = candidate_time
            break
    if candidate is None:
        candidate = (now + datetime.timedelta(days=1)).replace(hour=allowed_hours[0], minute=0, second=0, microsecond=0)
    return candidate

# --- Các hàm job ---
def modified_recent_update():
    start = time.time()
    try:
        print("[INFO] Bắt đầu cập nhật dữ liệu (modified/recent).")
        modified_recent_pull()
        
        print("[INFO] Bắt đầu lập chỉ mục dữ liệu (modified/recent).")
        indexing_modified_recent_cve()

        print("[INFO] Tự động quét lại!!!")
        auto_scan()
    except Exception as e:
        logger.error(f"Lỗi trong modified_recent_update: {e}")
        return  # Nếu có lỗi, không cập nhật next_run
    duration = time.time() - start
    logger.info(f"modified_recent_update completed successfully in {duration:.2f} seconds")

def complete_update():
    start = time.time()
    try:
        print("[INFO] Bắt đầu cập nhật toàn bộ dữ liệu.")
        complete_pull()
        
        print("[INFO] Bắt đầu lập chỉ mục toàn bộ dữ liệu CVE.")
        indexing_full_cve()
        
        print("[INFO] Bắt đầu lập chỉ mục dữ liệu CPE.")
        indexing_cpe()

        print("[INFO] Bắt đầu cập nhật template Nuclei")
        subprocess.run(['nuclei', '-ut'])

        print("[INFO] Tự động quét lại!!!")
        auto_scan()
    except Exception as e:
        logger.error(f"Lỗi trong complete_update: {e}")
        return
    duration = time.time() - start
    logger.info(f"complete_update completed successfully in {duration:.2f} seconds")

# --- Listener cập nhật file job store sau mỗi lần chạy job ---
def job_listener(event):
    global scheduler
    job_id = event.job_id
    # Lấy job từ scheduler
    job = scheduler.get_job(job_id) if scheduler else None
    if job and job.next_run_time:
        next_run = job.next_run_time
        last_updates = load_last_update()
        last_updates[job_id] = next_run.isoformat()
        save_last_update(last_updates)
        logger.info(f"Cập nhật next_run của job {job_id}: {next_run.isoformat()}")

# --- Hàm khởi động scheduler ---
def start_scheduler():
    global scheduler
    now = datetime.datetime.now(gmt7)
    last_updates = load_last_update()

    # Kiểm tra và thực hiện miss job khi khởi động server
    # Với complete_update (cron: chạy lúc 2:00 GMT+7)
    if "complete_update" in last_updates:
        last_complete = datetime.datetime.fromisoformat(last_updates["complete_update"])
        if now > last_complete:
            logger.info("complete_update bị trễ, chạy ngay...")
            complete_update()
            # Cập nhật next_run cho complete_update
            last_updates["complete_update"] = next_run_time_cron(2, 0).isoformat()
            # Nếu complete_update chạy, không cần chạy modified_recent_update => cập nhật luôn thời gian next_run
            last_updates["modified_recent_update"] = next_run_time_modified_recent_cron().isoformat()
            save_last_update(last_updates)
        else:
            print(f"Thời gian thực hiện complete_update tiếp theo: {last_complete}")
    else:
        # Nếu chưa có thông tin, khởi tạo
        last_updates["complete_update"] = next_run_time_cron(2, 0).isoformat()
        last_updates["modified_recent_update"] = next_run_time_modified_recent_cron().isoformat()
        save_last_update(last_updates)

    # Với modified_recent_update (cron: chạy vào các giờ chẵn ngoại trừ 2)
    if "modified_recent_update" in last_updates:
        last_modified = datetime.datetime.fromisoformat(last_updates["modified_recent_update"])

        # Nếu trễ và không nằm trong khung giờ complete_update (2h), chạy job
        if now > last_modified:
            # Chỉ chạy nếu giờ hiện tại khác 2 (vì lúc 2 sẽ chạy complete_update)
            if now.hour != 2:
                logger.info("modified_recent_update bị trễ, chạy ngay...")
                modified_recent_update()
            # Cập nhật next_run dù có chạy hay không
            last_updates["modified_recent_update"] = next_run_time_modified_recent_cron().isoformat()
            save_last_update(last_updates)
        else:
            print(f"Thời gian thực hiện modified-recent_update tiếp theo: {last_modified}")


    # Cấu hình scheduler (không dùng persistent job store của APScheduler)
    executors = {'default': ThreadPoolExecutor(1)}
    scheduler = BackgroundScheduler(executors=executors, timezone=gmt7)
    scheduler.add_listener(job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    scheduler.start()

    # Thêm các job mới với replace_existing=True để đảm bảo không trùng lặp
    scheduler.add_job(
        complete_update,
        'cron',
        hour=2,
        minute=0,
        second=0,
        id='complete_update',
        max_instances=1,
        coalesce=True,
        misfire_grace_time=86340,
        replace_existing=True
    )
    scheduler.add_job(
        modified_recent_update,
        'cron',
        hour="0,4,6,8,10,12,14,16,18,20,22",
        minute=0,
        second=0,
        id='modified_recent_update',
        max_instances=1,
        coalesce=True,
        misfire_grace_time=7199,
        replace_existing=True
    )
