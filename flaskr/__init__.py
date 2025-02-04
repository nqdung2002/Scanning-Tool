import os
from flask_socketio import SocketIO
from flask import Flask

socketio = SocketIO()

def create_app(test_config=None):
    # Tạo và cấu hình ứng dụng
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

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

    from . import db, auth, blog, scan
    app.register_blueprint(auth.bp)
    app.register_blueprint(blog.bp)
    app.register_blueprint(scan.bp)
    app.add_url_rule('/', endpoint='scan')
    db.init_app(app)

    # Khởi tạo socketio
    socketio.init_app(app)

    return app