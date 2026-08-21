from app import app
from database import init_db

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
