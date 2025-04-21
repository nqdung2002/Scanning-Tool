import os, sys, signal, time, threading
from flaskr.config.config import Config
from flaskr.function.tor_init import ensure_tor_running, stop_tor, renew_tor_ip
from flask_socketio import SocketIO
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail

socketio = SocketIO()
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
scheduler_started = False

def create_app(test_config=None):
    # Tạo và cấu hình ứng dụng
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    if test_config is None:
        # Tải cấu hình instance nếu có, không ghi đè cấu hình mặc định
        app.config.from_pyfile('config.py', silent=True)

    else:
        app.config.from_mapping(test_config)

    # Đảm bảo thư mục instance tồn tại
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Đăng ký blueprint
    from . import auth, scan, monitor
    from .function import export_report
    app.register_blueprint(auth.bp)
    app.register_blueprint(scan.bp)
    app.register_blueprint(monitor.bp)
    app.register_blueprint(export_report.bp)
    app.add_url_rule('/', endpoint='scan')

    # Khởi tạo server Tor
    global scheduler_started 
    ensure_tor_running()
    
    # Khởi tạo database và migrate
    db.init_app(app)
    migrate.init_app(app, db)
    with app.app_context():
        db.create_all()
        mail = Mail(app)
        # Khởi tạo SocketIO
        socketio.init_app(app)
        if not scheduler_started:
            scheduler_started = True  # Đánh dấu tiến trình đã khởi chạy
            from .function.data_auto_update import start_scheduler
            start_scheduler()

    signal.signal(signal.SIGINT, handle_exit_signal)
    
    # Xoay IP Tor mỗi 120s
    def tor_ip_rotation_thread():
        while True:
            renew_tor_ip()
            time.sleep(120)
    threading.Thread(target=tor_ip_rotation_thread, daemon=True).start()

    return app

def handle_exit_signal(signal, frame):
    print("Shutting down...")
    try:
        stop_tor()
        print("Đã dừng Tor")
    except Exception as e:
        print(f"Lỗi khi dừng Tor:  {e}")
    sys.exit(0)
