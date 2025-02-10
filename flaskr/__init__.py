import os
from flaskr.config.config import Config
from flask_socketio import SocketIO
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

socketio = SocketIO()
db = SQLAlchemy()
migrate = Migrate()

def create_app(test_config=None):
    # Tạo và cấu hình ứng dụng
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    if test_config is None:
        # tải cấu hình instance, nếu có, khi không ghi đè cấu hình mặc định
        app.config.from_pyfile('config.py', silent=True)
    else:
        # tải cấu hình test nếu được truyền vào
        app.config.from_mapping(test_config)

    # đảm bảo thư mục instance tồn tại
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import auth, blog, scan
    app.register_blueprint(auth.bp)
    app.register_blueprint(blog.bp)
    app.register_blueprint(scan.bp)
    app.add_url_rule('/', endpoint='scan')\
    
    db.init_app(app)
    migrate.init_app(app, db)    
    with app.app_context():
        db.create_all()

    # Khởi tạo socketio
    socketio.init_app(app)

    # In ra giá trị của SQLALCHEMY_DATABASE_URI để kiểm tra kết nối
    print(f"Connected to database: {app.config['SQLALCHEMY_DATABASE_URI']}")

    return app