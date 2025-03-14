from flaskr import create_app, socketio
from flaskr.monitor import start_watchlist_threads

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        start_watchlist_threads()
    socketio.run(app, debug=True)