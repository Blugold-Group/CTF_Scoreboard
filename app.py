from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory, Blueprint
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pyotp, os, secrets, markdown, sqlite3, logging, requests
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

from config import *
from helpers import *
from routes.ctf import ctf_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(64)

load_dotenv()

# API key defined in .env. Must match key defined in the Discord bot's .env file.
blu_api_key = os.getenv('BLU_API_KEY')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')

# Register blueprints (see readme for more info)
app.register_blueprint(ctf_bp)

login_manager = LoginManager(app)
login_manager.login_view = "login"

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)

# Using rotating logs so that our log file doesn't get too big/unmanageable. Will overwrite old logs
handler = RotatingFileHandler(LOG_FILE, maxBytes=1000000, backupCount=10)

# Setting up user login logging. LOG_FILE defined in config.py
# RotatingFileHandler dependency can be removed by removing the 'handlers' arg and adding 'filename=LOG_FILE'
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[handler])

werkzeug_logger = logging.getLogger('werkzeug')

# filtering out HTTP requests for static files
class IgnoreStaticFilesFilter(logging.Filter):
    def filter(self, record):
        ignored_paths = ["/static/", "/favicon.ico", "HTTP/1.1"]
        return not any(path in record.getMessage() for path in ignored_paths)

werkzeug_logger.addFilter(IgnoreStaticFilesFilter())

# Set up the user loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            return User(id=user[0], username=user[1], otp_secret=user[3], lock_permissions=user[4], is_admin=bool(user[5]))
        return None

class User(UserMixin):
    def __init__(self, id, username, otp_secret, lock_permissions, is_admin=False):
        self.id = id
        self.username = username
        self.otp_secret = otp_secret
        self.is_admin = is_admin
        self.lock_permissions = lock_permissions

    def verify_otp(self, otp):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(otp)


# If the database doesn't exist, create it
init_db()

# Icon in browser tab
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static/images', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        

        username = request.form['username']
        password = request.form['password']
        otp = request.form['otp']


        """
        # For development
        user_data = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

        user = User(id=user_data['id'], username=user_data['username'], otp_secret=user_data['otp_secret'], lock_permissions=user_data['lock_permissions'], is_admin=bool(user_data['is_admin']))
        login_user(user)
        return redirect(url_for('dashboard'))

        """
        
        # Fetch user from DB
        user_data = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if user_data and check_password_hash(user_data['password'], password):
            user = User(id=user_data['id'], username=user_data['username'], otp_secret=user_data['otp_secret'], lock_permissions=user_data['lock_permissions'], is_admin=bool(user_data['is_admin']))
            #if user.verify_otp(otp):
            #    login_user(user)
            #    return redirect(url_for('dashboard'))
            #else:
            #    flash("Invalid 2FA code", "error")

            login_user(user)
            session["user_id"] = user.id

            # log a login attempt with a different message depending on is_admin
            if current_user.is_admin:
                logging.info(f"Admin logged in: {username} (ID: {user.id})")
            else:
                logging.info(f"User logged in: {username} (ID: {user.id})")

            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "error")

            # log failed login attempt
            logging.warning(f"Failed login attempt: {username}")

    return render_template("login.html")

@app.route("/add_user", methods=["GET", "POST"])
@login_required
def add_user():

    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        otp_secret = pyotp.random_base32()  # Generate a random 2FA secret for the user
        lock_permissions = request.form['lock_permissions']
        hashed_password = generate_password_hash(password)  # Hash the password before storing
        try:
            is_admin = request.form['is_admin']
            if is_admin == "on":
                is_admin=1
            else:
                is_admin=0

        except:
            is_admin=0

        
        # Insert the new user into the database
        query_db('INSERT INTO users (username, password, otp_secret, lock_permissions, is_admin, tags) VALUES (?, ?, ?, ?, ?, ?)', 
                 [username, hashed_password, otp_secret, lock_permissions, is_admin, " "])
        
        flash("User added successfully", "success")
        
        # log a created user. use different log levels depending on if created account is_admin
        if is_admin:
            logging.warning(f"ADMIN USER CREATED: {username} BY USER: {current_user.username} (ID: {current_user.id}) from IP addr: {request.remote_addr}")
        else:
            logging.info(f"User created: {username} by user: {current_user.username} (ID: {current_user.id})")

        return redirect(url_for('dashboard'))

    return render_template("add_user.html")

# Shows a preview of all of open bounties and ctfs
@app.route("/dashboard")
@app.route("/")
def dashboard():

    current_date = datetime.now().strftime('%Y-%m-%d')  # Get today's date

    # Fetch all CTFs along with the number of challenges and their status (open/closed)
    ctfs = query_db('''
    SELECT c.id, c.name, c.start_date, c.end_date, 
           (SELECT COUNT(*) FROM challenge WHERE ctf_id = c.id) AS challenge_count
    FROM ctf c
    ORDER BY c.end_date >= ?, c.end_date DESC
    ''', (current_date,))

    # Separate CTFs into open and closed
    open_ctfs = [ctf for ctf in ctfs if ctf['end_date'] >= current_date]

    # Defining "closing soon" as ending within 3 days from current_date
    # CTF_CLOSING_SOON_DAYS is defined in config.py
    closing_soon_threshold = (datetime.now() + timedelta(days=CTF_CLOSING_SOON_DAYS)).strftime('%Y-%m-%d')
    closing_soon_ctfs = [ctf for ctf in open_ctfs if current_date <= ctf['end_date'] <= closing_soon_threshold]


    bounties = query_db("SELECT * FROM bug_bounties ORDER BY status, id DESC")

    is_admin = False
    if current_user.is_authenticated:
        is_admin = current_user.is_admin


    return render_template("dashboard.html", open_ctfs=open_ctfs, closing_soon_ctfs=closing_soon_ctfs, bounties=bounties, is_admin=is_admin)

@app.route("/logout")
@login_required
def logout():
    logging.info(f"User logged out: {current_user.username} (ID: {current_user.id})")
    logout_user()
    return redirect(url_for("login"))

@app.route("/add_activity", methods=["GET", "POST"])
@login_required
def add_activity():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        name = request.form['name']
        points = request.form['points']
        query_db('INSERT INTO activities (name, points) VALUES (?, ?)', [name, points])
        flash("Activity added successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template("add_activity.html")

@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        logging.warning(f"Non-admin user attempted to access admin-only page: {current_user.username} (ID: {current_user.id})")
        return redirect(url_for('dashboard'))

    users = query_db('SELECT * FROM users')
    activities = query_db('SELECT * FROM activities')
    logging.info(f"User accessed admin-only page: {current_user.username} (ID: {current_user.id})")
    return render_template("admin.html", users=users, activities=activities)

@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        logging.warning(f"Non-admin user attempted to access admin-only page: {current_user.username} (ID: {current_user.id})")
        return redirect(url_for('dashboard'))

    user_data = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        new_password_hash = generate_password_hash(password)
        query_db('UPDATE users SET username = ?, password = ? WHERE id = ?', [username, new_password_hash, user_id])
        flash("User updated successfully", "success")
        return redirect(url_for('dashboard'))
    logging.info(f"User accessed admin-only page: {current_user.username} (ID: {current_user.id})")
    return render_template("edit_user.html", user=user_data)

@app.route("/scoreboard")
def scoreboard():
    users = query_db('SELECT * FROM users')
    user_scores = []

    for user in users:
        score = 0
        user_activities = query_db('''
            SELECT a.points
            FROM user_activities ua
            JOIN activities a ON ua.activity_id = a.id
            WHERE ua.user_id = ?
        ''', [user['id']])

        score = sum(activity['points'] for activity in user_activities)
        user_scores.append((user, score))

    user_scores = sorted(user_scores, key=lambda x: x[1], reverse=True)
    return render_template("scoreboard.html", user_scores=user_scores)


# Route for seeing all bug bounties
@app.route('/bounties')
@app.route('/bounty')
def bounties():
    bounties = query_db("SELECT * FROM bug_bounties ORDER BY status, id DESC")

    is_admin = False
    if current_user.is_authenticated:
        is_admin = current_user.is_admin

    return render_template('bounties.html', bounties=bounties, is_admin=is_admin)

# Route to add a new bug bounty
@app.route('/add_bounty', methods=['GET', 'POST'])
@login_required
def add_bounty():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        prize = str(request.form['prize'])

        # Insert the new bounty into the database
        query_db("""
            INSERT INTO bug_bounties (title, description, status, prize, completed_by, completion_dates) 
            VALUES (?, ?, ?, ?, ?, ?);
        """, (title, description, 'open', prize, '', ''))
        
        return redirect(url_for('dashboard'))
    return render_template('add_bounty.html')

# Route to edit a bug bounty (mark it completed and who completed it)
@login_required
@app.route('/edit/<int:bounty_id>', methods=['GET', 'POST'])

def edit_bounty(bounty_id):
    bounty = query_db("SELECT * FROM bug_bounties WHERE id = ?", (bounty_id,), one=True)

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        prize = request.form['prize']
        status = request.form['status']
        completed_by = request.form['completed_by']
        completion_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Prepare the completed_by and completion_dates lists if status is 'closed'
        completed_by_list = bounty['completed_by'].split(',') if bounty['completed_by'] else []
        completion_dates_list = bounty['completion_dates'].split(',') if bounty['completion_dates'] else []

        if completed_by and status == 'closed':
            completed_by_list.append(completed_by)
            completion_dates_list.append(completion_date)

        # Update the bounty data in the database
        query_db("""
            UPDATE bug_bounties
            SET title = ?, description = ?, prize = ?, status = ?, 
                completed_by = ?, completion_dates = ?
            WHERE id = ?;
        """, (title, description, prize, status, ','.join(completed_by_list), ','.join(completion_dates_list), bounty_id))

        return redirect(url_for('bounties'))

    return render_template('edit_bounty.html', bounty=bounty)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/about/badges')
def badges():

    with open("guides/badges.md", 'r') as file:
        content = file.readlines()
            
        content = ''.join(content)

    html = markdown.markdown(content)

    title = "Badges"

    return render_template('guide.html', content=html, title=title)


@app.route('/members')
@app.route('/users')
def view_members():

    usernames = []
    points = []
    total_user_challenges = []
    tags = []
    discord_handles = []

    user_challenge_points = get_all_user_challenge_points()

    for user_id, challenge_points in user_challenge_points.items():
        usernames.append(get_username_by_user_id(user_id))
        points.append(sum(challenge_points.values()))
        total_user_challenges.append(len(challenge_points))
        tag = get_user_tags(get_username_by_user_id(user_id))

        if tag:
            tags.append(tag)
        else:
            tags.append("")

        discord_handle = query_db('SELECT discord_handle FROM users WHERE id = ?', [user_id], one=True)

        if discord_handle and discord_handle[0]:
            discord_handles.append(discord_handle[0])
        else:
            discord_handles.append("")

    return render_template('members.html', usernames=usernames, points=points, total_user_challenges=total_user_challenges, tags=tags, discord_handles=discord_handles)

@app.route('/admin_reset_password', methods=['GET', 'POST'])
@login_required
def admin_reset_password():

    if not current_user.is_admin:
        logging.warning(f"Non-admin user attempted to access admin-only page: {current_user.username} (ID: {current_user.id})")
        logging.warning(f"{current_user.username} attempted to access /admin_reset_password!")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if query_db('SELECT * FROM users WHERE username = ?', [username], one=True) is not None:
            if password == confirm_password:

                hashed_password = generate_password_hash(password)
                query_db('UPDATE users SET password = ? WHERE username = ?', [hashed_password, username])

                flash('Password reset successful!', 'success')
                return redirect(url_for('admin_reset_password'))
            else:
                flash('Passwords do not match!', 'error')
        else:
            flash('User not found!', 'error')

    # Render the reset password form (GET request)
    logging.info(f"User accessed admin-only page: {current_user.username} (ID: {current_user.id})")
    return render_template('admin_reset_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():


    if request.method == 'POST':
        old_password = request.form.get('old_password')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        user_data = query_db('SELECT * FROM users WHERE username = ?', [current_user.username], one=True)

        if user_data is not None:
            if password == confirm_password:

                check_password_hash(user_data['password'], old_password)

                new_hashed_password = generate_password_hash(password)
                query_db('UPDATE users SET password = ? WHERE username = ?', [new_hashed_password, current_user.username])

                flash('Password reset successful!', 'success')
                return redirect(url_for('reset_password'))
            else:
                flash('Passwords do not match!', 'error')
        else:
            flash('User not found!', 'error')

    # Render the reset password form (GET request)
    return render_template('reset_password.html')

# The Discord API will communicate with this route during authorization
@app.route('/discord/callback')
def discord_callback():

    try:
        code = request.args.get('code')
        if not code:
            return "Discord authorization failed: No code provided", 400

        # Contructing data to send to discord to get a token
        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_URI,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(f"{DISCORD_API_ENDPOINT}/oauth2/token", data=data, headers=headers)

        if response.status_code != 200:
            return f"Failed to retrieve access token: {response.text}", 400

        token = response.json()["access_token"]

        # Get user info
        headers = {"Authorization": f"Bearer {token}"}
        user_info = requests.get(f"{DISCORD_API_ENDPOINT}/users/@me", headers=headers).json()

        # Because of how things are setup right now, make sure to always include the discriminator (e.g. #1234)...
        # despite Discord no longer fully maintaining discriminators. For most accounts, it will be #0.
        discord_handle = f"{user_info['username']}#{user_info['discriminator']}"
        
        # Check to ensure discord_handle is unique
        existing_user = query_db("SELECT id FROM users WHERE discord_handle = ?", (discord_handle,), one=True)
        if existing_user:
            return "This Discord account is already linked to another user.", 400

        user_id = session.get("user_id")
        query_db("UPDATE users SET discord_handle = ? WHERE id = ?", (discord_handle, user_id))

        return redirect(url_for("dashboard"))
    except Exception as e:
        return f"An error occurred: {str(e)}", 500

# This is an end-user accessible route that uses Discord OAuth2 to link a Discord account.
# After the user authorizes through Discord, the remote API communicates with our /discord/callback.
@app.route("/connect_discord")
@login_required
def connect_discord():

    discord_auth_url = (
        f"https://discord.com/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify"
    )
    print("Generated Discord oauth2 url:", discord_auth_url)
    return redirect(discord_auth_url)

#curl -G "http://127.0.0.1:5000/api/totalpoints" --data-urlencode "discord_handle=testeekrats#0"
@app.route('/api/totalpoints', methods=['GET'])
def api_get_points():
    discord_handle = request.args.get('discord_handle')
    if not discord_handle:
        return {'error': 'Discord handle is required'}, 400
    
    # get user_id from discord_handle
    user = query_db('SELECT id FROM users WHERE discord_handle = ?', (discord_handle,), one=True)
    if not user:
        return {'error': 'No user found for the given Discord handle'}, 404

    user_id = user['id']
    challenge_points = get_user_challenge_points(user_id)

    if challenge_points:
        total_points = sum(challenge_points.values())
    else:
        total_points = 0

    return {'discord_handle': discord_handle,
            'total_points': total_points}, 200

# List all CTFs in the database and return dictionary with relevant data for each
@app.route('/api/listctfs', methods=['GET'])
def api_list_ctfs():

    ctfs = query_db('SELECT id, name, start_date, end_date FROM ctf ORDER BY id ASC')
    if not ctfs:
        return {'error': 'No CTFs found'}, 404

    return {'ctfs': [dict(ctf) for ctf in ctfs]}, 200

# API create a new CTF
@app.route('/api/createctf', methods=['POST'])
def api_create_ctf():

    api_key = request.headers.get('X-API-KEY')
    if api_key and api_key != blu_api_key:
        return {'error': 'Unauthorized'}, 401

    data = request.get_json()
    name = data.get('name')
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    if not all([name, start_date, end_date]):
        return {'error': 'A required field is missing'}, 400

    query_db('INSERT INTO ctf (name, start_date, end_date) VALUES (?, ?, ?)', (name, start_date, end_date))
    return {'success': True}, 201

@app.route('/api/challenges', methods=['GET'])
def api_get_challenges():
    ctf_id = request.args.get('ctf_id')
    if not ctf_id:
        return {'error': 'ctf_id is required'}, 400

    challenges = query_db('SELECT * FROM challenge WHERE ctf_id = ?', (ctf_id,))
    return {'challenges': [dict(row) for row in challenges]}, 200

@app.route('/api/createchallenge', methods=['POST'])
def api_create_challenge():
    api_key = request.headers.get('X-API-KEY')
    if api_key and api_key != blu_api_key:
        return {'success': False, 'error': 'Unauthorized'}, 401

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    points = data.get('points')
    ctf_id = data.get('ctf_id')
    flag = data.get('flag')

    if not (name and description and points and ctf_id):
        return {'success': False, 'error': 'A required field is missing'}, 400

    query_db('''
        INSERT INTO challenge (ctf_id, name, description, points, flag)
        VALUES (?, ?, ?, ?, ?)
    ''', (ctf_id, name, description, points, flag))

    return {'success': True, 'message': 'Challenge created successfully'}, 201

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")
