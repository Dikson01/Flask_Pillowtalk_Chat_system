from flask import Flask, render_template, url_for, redirect, flash, request, session,jsonify
from forms import UserForm, LoginForm, ResetPasswordForm, ForgotPasswordForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_sqlalchemy import SQLAlchemy
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_socketio import SocketIO, join_room, leave_room, send
import uuid
import time

app = Flask(__name__)
app.secret_key = 'TopSecretkey'
csrf = CSRFProtect(app)
s = URLSafeTimedSerializer(app.secret_key)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

socketio = SocketIO(app)

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "diksonsharma616@gmail.com"
app.config['MAIL_PASSWORD'] = "diko kzha cvkr wjov"
app.config['MAIL_DEFAULT_SENDER'] = "diksonsharma616@gmail.com"

db.init_app(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

interest_waiting = {
    "movies": [],
    "travel": [],
    "food": [],
    "technology": [],
    "books": [],
    "fitness": [],
    "music": [],
    "gaming": [],
    "relationships": [],
    "career": [],
    "science": [],
    "sports": [],
    "anime": [],
    "memes": [],
    "life": [],
    "no_preference": []
}


@app.route('/')
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

        if existing_user:
            flash("username or email already exist try another.", 'danger')
            return render_template("form.html", form=form)

        hashed_password = generate_password_hash(password)
        is_admin = User.query.first() is None

        new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        msg = Message("Welcome To Dikson's app!", recipients=[new_user.email])
        msg.body = f'''Hi {new_user.username},\nWelcome to our Flask app!\nLet us know if you ever need help.\nCheers,\nTeam Dikson'''
        mail.send(msg)

        flash('Registration successful!', 'success')
        return redirect(url_for("register"))
    else:
        print(form.errors)

    return render_template("form.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password!", "danger")
    return render_template("login.html", form=form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout successfully", "success")
    return redirect(url_for("index"))

@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('resetpassword', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[user.email])
            msg.body = f'''Hi {user.username},\nTo reset your password, click the link below:\n{reset_url}\nIf you didn’t request this, ignore this email.'''
            mail.send(msg)
            flash("A password reset link has been sent to your email.", "info")
            return redirect(url_for('login'))
        else:
            flash("No account found with that email.", "danger")
    return render_template("forgotpassword.html", form=form)

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def resetpassword(token):
    form = ResetPasswordForm()
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash("The reset link has expired. Please request a new one.", "danger")
        return redirect(url_for("forgotpassword"))
    except BadSignature:
        flash("Invalid or tampered link.", "danger")
        return redirect(url_for("forgotpassword"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("No user found with that email.", "danger")
        return redirect(url_for("forgotpassword"))

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been reset successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("resetpassword.html", form=form)

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return "Access Denied. Admins only!", 403
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route("/deleteuser/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "Access Denied. Admin only!", 403
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash("You can't delete yourself!", "danger")
        return redirect(url_for('admin'))
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f"User: {user_to_delete.username} is deleted successfully!", "success")
    return redirect(url_for("admin"))


active_sessions = set()
paired_users = {}

@app.before_request
def track_leaving_waiting():
    if current_user.is_authenticated and request.endpoint not in ["waiting", "join_chat", "static", "check_match", "chat"]:
        uid = current_user.id
        active_sessions.discard(uid)
        for topic in interest_waiting:
            interest_waiting[topic] = [(u, t) for u, t in interest_waiting[topic] if u != uid]
        session.pop("interest", None)

@app.route('/join-chat', methods=["POST"])
@login_required
def join_chat():
    selected_interest = request.form.get("interest")
    if not selected_interest:
        flash("Please select a topic.", "danger")
        return redirect(url_for("dashboard"))

    user_id = current_user.id

    for topic, queue in interest_waiting.items():
        interest_waiting[topic] = [(uid, ts) for uid, ts in queue if uid in active_sessions]

    if user_id in paired_users:
        room_id = paired_users.pop(user_id)
        return redirect(url_for("chat", room_id=room_id))

    queue = interest_waiting[selected_interest]
    ids_in_queue = [uid for uid, _ in queue]
    if user_id not in ids_in_queue:
        queue.append((user_id, time.time()))
        active_sessions.add(user_id)
        session['interest'] = selected_interest

    if len(queue) >= 2:
        user1, _ = queue.pop(0)
        user2, _ = queue.pop(0)
        room_id = str(uuid.uuid4())[:8]
        paired_users[user1] = room_id
        paired_users[user2] = room_id
        active_sessions.discard(user1)
        active_sessions.discard(user2)
        if user_id in (user1, user2):
            return redirect(url_for("chat", room_id=room_id))

    return redirect(url_for("waiting"))

@app.route('/waiting')
@login_required
def waiting():
    user_id = current_user.id
    interest = session.get('interest')
    if not interest:
        flash("Please choose an interest again.", "warning")
        return redirect(url_for("dashboard"))

    for topic, queue in interest_waiting.items():
        interest_waiting[topic] = [(uid, ts) for uid, ts in queue if uid in active_sessions]

    queue = interest_waiting[interest]
    ids_in_queue = [uid for uid, _ in queue]
    if user_id not in ids_in_queue:
        queue.append((user_id, time.time()))
        active_sessions.add(user_id)

    if len(queue) >= 2:
        user1, _ = queue.pop(0)
        user2, _ = queue.pop(0)
        room_id = str(uuid.uuid4())[:8]
        paired_users[user1] = room_id
        paired_users[user2] = room_id
        active_sessions.discard(user1)
        active_sessions.discard(user2)
        if user_id in (user1, user2):
            return redirect(url_for("chat", room_id=room_id))

    return render_template("waiting.html")

@app.route("/check-match")
@login_required
def check_match():
    user_id = current_user.id
    if user_id in paired_users:
        room_id = paired_users.pop(user_id)
        return jsonify({"redirect": url_for("chat", room_id=room_id)})
    return jsonify({"redirect": None})

@socketio.on('disconnect')
def handle_disconnect():
    uid = current_user.get_id()
    if uid:
        uid = int(uid)
        print(f"User {uid} disconnected")
        active_sessions.discard(uid)
        for topic in interest_waiting:
            interest_waiting[topic] = [(u, t) for u, t in interest_waiting[topic] if u != uid]
        if uid in paired_users:
            del paired_users[uid]

@app.route('/chat/<room_id>')
@login_required
def chat(room_id):
    return render_template("chat.html", room_id=room_id)

@socketio.on('message')
def handle_message(data):
    room = data.get('room')
    msg = data.get('msg')
    sender = data.get('sender')
    print(f"Received message: {msg} from {sender} in room {room}")  # Debugging log
    send({'msg': msg, 'sender': sender}, to=room)


@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    sender = data.get('sender')
    join_room(room)
    print(f"User {sender} joined room: {room}")

    room_members = socketio.server.manager.rooms.get(request.namespace, {}).get(room, set())
    
    # If this is the second user joining, announce to all (including this new one)
    if len(room_members) == 2:
        send({'msg': 'A user has joined the chat.', 'sender': 'system'}, room=room)
        
        # Start 7-minute timer when both users joined
        socketio.emit('start_timer', {'duration': 420}, room=room)  # 420 seconds = 7 min



@socketio.on('leave_chat')
def handle_leave_chat(data):
    room = data.get('room')
    leave_room(room)
    print(f"User left room: {room}")
    # Notify others in the room that this user has left
    send({'msg': 'The other user has left the chat.', 'sender': 'system'}, to=room)


if __name__ == '__main__':
    socketio.run(app, debug=True)
