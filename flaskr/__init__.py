import os
from flaskr.config.config import Config
from flask_socketio import SocketIO
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail

socketio = SocketIO()
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

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
    from . import auth, blog, scan, monitor
    app.register_blueprint(auth.bp)
    app.register_blueprint(blog.bp)
    app.register_blueprint(scan.bp)
    app.register_blueprint(monitor.bp)
    app.add_url_rule('/', endpoint='scan')
    
    # Khởi tạo database và migrate
    db.init_app(app)
    migrate.init_app(app, db)
    with app.app_context():
        db.create_all()
        mail = Mail(app)
        # Khởi tạo SocketIO
        socketio.init_app(app)
        if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            from .function.data_auto_update import start_scheduler
            start_scheduler()


    # Khởi chạy scheduler cập nhật tự động ở tiến trình con

    return app
