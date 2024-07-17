""""""
import logging
import re
import sys
from logging import handlers
from pathlib import Path
from random import randint, uniform

from flask import Flask, redirect, render_template, url_for, request, session
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from loki_logger_handler.loki_logger_handler import LokiLoggerHandler
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash


class NoEscape(logging.Filter):
    """Removes the escape sequences from 'werkzeug's logs, such as the colouring tags."""
    def __init__(self):
        self.regex = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')

    def strip_esc(self, s):
        try:
            # String-like.
            _s = self.regex.sub("", s)
            return _s.replace('"', "").replace("\n", " ")
        except:
            # Non-string-like.
            return s

    def filter(self, record: logging.LogRecord) -> int:
        record.msg = self.strip_esc(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(map(self.strip_esc, record.args))
        return 1


ACTIVE_USERS = {}

(log_path := Path.cwd().absolute() / "logs").mkdir(parents=True, exist_ok=True)

loki_handler = LokiLoggerHandler(
    url="http://loki:3100/loki/api/v1/push",
    labels={"application": "Carnivorous Garden", "environment": "Develop"},
    labelKeys={},
)

# Application Logger Setup
app_logger = logging.getLogger("myapp")
app_logger.setLevel(logging.DEBUG)

app_log_handler = handlers.RotatingFileHandler(log_path / "carnivorous-garden.log", maxBytes=10000, backupCount=5)
app_log_handler.setLevel(logging.DEBUG)
app_log_handler.setFormatter(logging.Formatter('time="%(asctime)s" logger="%(name)s" level="%(levelname)s" message="%(message)s"'))
app_logger.addHandler(app_log_handler)

sys_log_handler = logging.StreamHandler(sys.stdout)
sys_log_handler.setLevel(logging.DEBUG)
sys_log_handler.setFormatter(logging.Formatter('time="%(asctime)s" logger="%(name)s" level="%(levelname)s" message="%(message)s"'))
app_logger.addHandler(sys_log_handler)
app_logger.addHandler(loki_handler)

# Werkzeug Logger Setup
# Disable the colour formatting escapes in the 'werkzeug' logs to prevent logging errors.
werkzeug_logger = logging.getLogger("werkzeug")
werkzeug_logger.setLevel(logging.DEBUG)

werkzeug_log_handler = handlers.RotatingFileHandler(log_path / "carnivorous-garden_werkzeug.log", maxBytes=10000, backupCount=5)
werkzeug_log_handler.addFilter(NoEscape())
werkzeug_log_handler.setLevel(logging.DEBUG)
werkzeug_log_handler.setFormatter(logging.Formatter('time="%(asctime)s" logger="%(name)s" level="%(levelname)s" message="%(message)s"'))
werkzeug_logger.addHandler(werkzeug_log_handler)

werkzeug_sys_log_handler = logging.StreamHandler(sys.stdout)
werkzeug_sys_log_handler.setLevel(logging.DEBUG)
werkzeug_sys_log_handler.setFormatter(logging.Formatter('time="%(asctime)s" logger="%(name)s" level="%(levelname)s" message="%(message)s"'))
werkzeug_logger.addHandler(werkzeug_sys_log_handler)

# Flask App
app = Flask(__name__)
app.logger = app_logger
app.config["SECRET_KEY"] = "plantsarecool1234"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///carnivorous_green_house.db"
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", engineio_logger=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    plants = db.relationship("Plant", backref="owner", lazy=True)


class Plant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    plant_type = db.Column(db.String(50), nullable=False)
    health_data = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


@app.route("/")
def index():
    error_mode = session.get("error_mode", False)
    return render_template("index.html", error_mode=error_mode)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error_mode = session.get("error_mode", False)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            app.logger.info("New user created: %s", username)
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()  # Important to rollback the session to clean state.
            app.logger.error("Signup failed: Username '%s' already exists.", username)
            return render_template(
                "signup.html", error="That username is already taken, please choose another.", error_mode=error_mode
            )
        except Exception as e:
            db.session.rollback()
            app.logger.exception("An unexpected error of type %s, occurred during signup.", e.__class__.__name__)
            return render_template(
                "signup.html", error="An unexpected error occurred. Please try again.", error_mode=error_mode
            )
    return render_template("signup.html", error_mode=error_mode)


@app.route("/login", methods=["GET", "POST"])
def login():
    error_mode = session.get("error_mode", False)
    if request.method == "POST":
        if session.get("error_mode", False) and randint(0, 1):
            app.logger.error("Login process failed unexpectedly.")
            return "Login Error", 500

        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))
        return "Login Failed"
    return render_template("login.html", error_mode=error_mode)


@app.route("/logout")
def logout():
    session.get("error_mode", False)
    if session.get("error_mode", False) and randint(0, 1):
        app.logger.error("Logout failed due to session error.")
        return "Logout Error", 500

    session.pop("user_id", None)
    return redirect(url_for("index"))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    error_mode = session.get("error_mode", False)
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user = User.query.get(user_id)
    plants = Plant.query.filter_by(user_id=user_id).all()

    return render_template("dashboard.html", user=user, plants=plants, error_mode=error_mode)


@app.route("/toggle_error_mode", methods=["POST"])
def toggle_error_mode():
    current_mode = session.get("error_mode", False)
    session["error_mode"] = not current_mode  # Toggle the state.
    session.modified = True  # Make sure the change is saved.
    error_mode = "on" if session["error_mode"] else "off"
    app.logger.info("Error mode toggled to %s.", error_mode)
    return redirect(request.referrer or url_for("index"))


@socketio.on("add_plant")
def handle_add_plant(json):
    user_id = session.get("user_id")
    if not user_id or (session.get("error_mode", False) and randint(0, 1)):
        app.logger.error("Unauthorized or failed attempt to add plant.")
        emit("error", {"error": "Failed to add plant due to server error"}, room=request.sid)
        return
    plant_name = json.get("plant_name")
    plant_type = json.get("plant_type")
    new_plant = Plant(name=plant_name, plant_type=plant_type, health_data="Healthy", user_id=user_id)
    db.session.add(new_plant)
    db.session.commit()
    emit(
        "new_plant",
        {"plant_id": new_plant.id, "plant_name": new_plant.name, "plant_type": new_plant.plant_type},
        room=str(user_id),
    )
    app.logger.info("New plant %s added successfully.", plant_name)


@socketio.on("connect")
def handle_connect():
    user_id = session.get("user_id")
    if user_id:
        # Initialize or update the user's status including error mode.
        ACTIVE_USERS[user_id] = {"error_mode": session.get("error_mode", False)}
        join_room(str(user_id))
        app.logger.info(
            "User %s connected and joined their room with error mode %s.", user_id, ACTIVE_USERS[user_id]["error_mode"]
        )


@socketio.on("disconnect")
def on_disconnect():
    user_id = session.get("user_id")
    if user_id in ACTIVE_USERS:
        del ACTIVE_USERS[user_id]
        app.logger.info("User %s disconnected and was removed from active list.", user_id)


def simulate_plant_data():
    while True:
        with app.app_context():
            socketio.sleep(2)
            for user_id, user_info in list(ACTIVE_USERS.items()):
                try:
                    if user_info["error_mode"] and randint(0, 1):
                        # Log an error message and continue without sending data.
                        app.logger.warning("Failed to send data to: %s: Will retry later", user_id)
                        continue

                    plants = Plant.query.filter_by(user_id=user_id).all()
                    for plant in plants:
                        fake_data = {
                            "temperature": round(uniform(20.0, 30.0), 2),
                            "humidity": round(uniform(40.0, 60.0), 2),
                            "water_level": randint(1, 10),
                            "number_of_insects": randint(0, 10),
                        }
                        socketio.emit("update_plant", {"plant_id": plant.id, "data": fake_data}, room=str(user_id))
                        app.logger.debug("Simulated data for plant %s sent to user %s", plant.id, user_id)
                except Exception as e:
                    app.logger.error("Error in simulation thread for user %s: %s", user_id, str(e))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.start_background_task(simulate_plant_data)
    socketio.run(app=app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
