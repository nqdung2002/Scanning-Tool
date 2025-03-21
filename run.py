from flaskr import create_app, socketio
from flaskr.monitor import start_watchlist_threads
from flaskr.function.waf_monitor import start_monitoring_waf

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        start_watchlist_threads()
        start_monitoring_waf()
    socketio.run(app, debug=True)