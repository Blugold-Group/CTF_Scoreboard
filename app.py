import sqlite3
from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pyotp, os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

"""
import pyotp
totp = pyotp.TOTP(pyotp.random_base32())
print(totp.now())  # Display current OTP
print(totp.secret)  # Store this secret in your User model
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# SQLite3 Database path
DATABASE = 'database.db'

login_manager = LoginManager(app)
login_manager.login_view = "login"

# Initialize the database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            otp_secret TEXT NOT NULL,
            lock_permissions TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            points INTEGER NOT NULL
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activities (
            user_id INTEGER NOT NULL,
            activity_id INTEGER NOT NULL,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, activity_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (activity_id) REFERENCES activities(id)
        )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS locks (
                id INTEGER UNIQUE NOT NULL,
                name TEXT,
                permissions TEXT NOT NULL
            );
        ''')

        conn.execute('''
        CREATE TABLE IF NOT EXISTS ctf (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL
        )
        ''')

        conn.execute('''
        CREATE TABLE IF NOT EXISTS challenge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ctf_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            points INTEGER NOT NULL,
            flag TEXT NOT NULL,  -- Adding the flag column
            FOREIGN KEY (ctf_id) REFERENCES ctf(id)
        )
        ''')

        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_challenges (
            user_id INTEGER NOT NULL,
            challenge_id INTEGER NOT NULL,
            completed INTEGER DEFAULT 0,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (challenge_id) REFERENCES challenge(id),
            PRIMARY KEY (user_id, challenge_id)
        )
        ''')              

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS bug_bounties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT CHECK(status IN ('open', 'closed')) NOT NULL,
            prize TEXT NOT NULL,
            completed_by TEXT,  -- Comma-separated list of users who completed the bounty
            completion_dates TEXT  -- Comma-separated list of timestamps
        );
        """)

        conn.commit()

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

# Initialize the DB
init_db()

# Helper function to interact with the database
def query_db(query, args=(), one=False):
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, args)
        rv = cursor.fetchall()
        conn.commit()
        return (rv[0] if rv else None) if one else rv

# Function to add a CTF event
def add_ctf(name, start_date, end_date):
    query_db('''
    INSERT INTO ctf (name, start_date, end_date)
    VALUES (?, ?, ?)
    ''', (name, start_date, end_date))

# Function to add a challenge to a CTF
def add_challenge(ctf_id, name, description, points):
    query_db('''
    INSERT INTO challenge (ctf_id, name, description, points)
    VALUES (?, ?, ?, ?)
    ''', (ctf_id, name, description, points))

# Function to record a user's challenge completion
def complete_challenge(user_id, challenge_id):
    completion_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    query_db('''
    INSERT INTO challenge_completion (user_id, challenge_id, completion_date)
    VALUES (?, ?, ?)
    ''', (user_id, challenge_id, completion_date))

# Function to get challenges completed by a specific user
def get_user_completions(user_id):
    return query_db('''
    SELECT c.name, ch.completion_date 
    FROM challenge_completion ch
    JOIN challenge c ON ch.challenge_id = c.id
    WHERE ch.user_id = ?
    ''', (user_id,))

# Function to get all challenges in a specific CTF
def get_ctf_challenges(ctf_id):
    return query_db('''
    SELECT name, description, points 
    FROM challenge
    WHERE ctf_id = ?
    ''', (ctf_id,))

# Marks that a user has completed a challenge in a ctf
def mark_challenge_completed(user_id, challenge_id, submitted_flag):
    
    # Check if the challenge exists and retrieve its flag
    challenge_query = "SELECT id, flag FROM challenge WHERE id = ?"

    challenge = query_db(challenge_query, (challenge_id,), one=True)
    if not challenge:
        return False
    
    # Check if the user has already completed the challenge
    user_challenge_query = """
        SELECT completed FROM user_challenges WHERE user_id = ? AND challenge_id = ?
    """
    existing_entry = query_db(user_challenge_query, (user_id, challenge_id), one=True)
    
    timestamp = datetime.now().isoformat()  # current timestamp in ISO format
    if existing_entry:
        if existing_entry['completed'] == 1:
            return "already_submitted"
        
    # Checks if the submitted flag is correct
    stored_flag = challenge['flag']
    if submitted_flag != stored_flag:
        return "wrong_flag"
    
    # Insert a new record indicating challenge completion
    insert_query = """
        INSERT INTO user_challenges (user_id, challenge_id, completed, timestamp)
        VALUES (?, ?, 1, ?)
    """
    query_db(insert_query, (user_id, challenge_id, timestamp))

    return "success"

def get_ctf_statistics(ctf_id):
    # 1. Get total number of challenges and total points for the CTF
    query = '''
    SELECT COUNT(*), SUM(points)
    FROM challenge
    WHERE ctf_id = ?
    '''
    total_challenges, total_points = query_db(query, (ctf_id,), one=True)

    # 2. Get the number of users who participated (i.e., who completed at least one challenge)
    query = '''
    SELECT COUNT(DISTINCT user_id)
    FROM user_challenges
    JOIN challenge ON user_challenges.challenge_id = challenge.id
    WHERE challenge.ctf_id = ?
    '''
    total_users = query_db(query, (ctf_id,), one=True)

    # 3. Get number of completed challenges per user
    query = '''
    SELECT user_id, COUNT(*) AS completed_challenges
    FROM user_challenges
    JOIN challenge ON user_challenges.challenge_id = challenge.id
    WHERE challenge.ctf_id = ? AND user_challenges.completed = 1
    GROUP BY user_id
    '''
    completed_by_user = query_db(query, (ctf_id,))
    completed_challenges_by_user = {user_id: completed_challenges for user_id, completed_challenges in completed_by_user}

    # 4. Get total points per user
    query = '''
    SELECT user_challenges.user_id, SUM(challenge.points) AS total_points
    FROM user_challenges
    JOIN challenge ON user_challenges.challenge_id = challenge.id
    WHERE challenge.ctf_id = ? AND user_challenges.completed = 1
    GROUP BY user_challenges.user_id
    '''
    user_points = query_db(query, (ctf_id,))
    user_points_dict = {user_id: total_points for user_id, total_points in user_points}

    # 5. Get the names of the CTF event and its start/end dates
    query = '''
    SELECT name, start_date, end_date
    FROM ctf
    WHERE id = ?
    '''
    ctf_details = query_db(query, (ctf_id,), one=True)
    ctf_name, start_date, end_date = ctf_details

    # Format the output as a dictionary for readability
    statistics = {
        "CTF Name": ctf_name,
        "Start Date": start_date,
        "End Date": end_date,
        "Total Challenges": total_challenges,
        "Total Points Available": total_points,
        "Total Users Participated": total_users,
        "Completed Challenges by User": completed_challenges_by_user,
        "User Points": user_points_dict
    }

    return statistics

def get_username_by_user_id(user_id):
    query = "SELECT username FROM users WHERE id = ?"
    result = query_db(query, (user_id,), one=True)
    
    if result:
        return result['username']  # Return the username from the row
    else:
        return None  # Return None if no user found

# Hosts favicon
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
            #    flash("Invalid 2FA code", "danger")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")

        

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
        query_db('INSERT INTO users (username, password, otp_secret, lock_permissions, is_admin) VALUES (?, ?, ?, ?, ?)', 
                 [username, hashed_password, otp_secret, lock_permissions, is_admin])  # Default user is not admin
        
        flash("User added successfully", "success")
        return redirect(url_for('admin_dashboard'))

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

    bounties = query_db("SELECT * FROM bug_bounties ORDER BY status, id DESC")

    is_admin = False
    if current_user.is_authenticated:
        is_admin = current_user.is_admin


    return render_template("dashboard.html", open_ctfs=open_ctfs, bounties=bounties, is_admin=is_admin)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/add_activity", methods=["GET", "POST"])
@login_required
def add_activity():
    #if not current_user.is_admin:
    #    return redirect(url_for('dashboard'))

    if request.method == "POST":
        name = request.form['name']
        points = request.form['points']
        query_db('INSERT INTO activities (name, points) VALUES (?, ?)', [name, points])
        flash("Activity added successfully", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template("add_activity.html")

@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    users = query_db('SELECT * FROM users')
    activities = query_db('SELECT * FROM activities')
    return render_template("admin.html", users=users, activities=activities)

@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    user_data = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        new_password_hash = generate_password_hash(password)
        query_db('UPDATE users SET username = ?, password = ? WHERE id = ?', [username, new_password_hash, user_id])
        flash("User updated successfully", "success")
        return redirect(url_for('admin_dashboard'))

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

# CTFs Landing page
@app.route('/ctf')
def list_ctfs():
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
    closed_ctfs = [ctf for ctf in ctfs if ctf['end_date'] < current_date]

    is_admin = False
    if current_user.is_authenticated:
        is_admin = current_user.is_admin

    return render_template('list_ctfs.html', open_ctfs=open_ctfs, closed_ctfs=closed_ctfs, is_admin=is_admin)

# Route to create a new CTF
@app.route('/create_ctf', methods=['GET', 'POST'])
@login_required
def create_ctf():

    if not current_user.is_admin:
        flash("You are not authorized to create CTFs.", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Insert CTF into the database
        query_db('''
        INSERT INTO ctf (name, start_date, end_date)
        VALUES (?, ?, ?)
        ''', (name, start_date, end_date))

        flash('CTF created successfully!', 'success')
        return redirect(url_for('list_ctfs'))

    return render_template('create_ctf.html')

# Route to edit an existing CTF
@app.route('/edit_ctf/<int:ctf_id>', methods=['GET', 'POST'])
@login_required
def edit_ctf(ctf_id):

    if not current_user.is_admin:
        flash("You are not authorized to create CTFs.", "danger")
        return redirect(url_for('dashboard'))

    ctf = query_db('SELECT * FROM ctf WHERE id = ?', (ctf_id,), one=True)

    if request.method == 'POST':
        name = request.form['name']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Update CTF details in the database
        query_db('''
        UPDATE ctf SET name = ?, start_date = ?, end_date = ?
        WHERE id = ?
        ''', (name, start_date, end_date, ctf_id))

        flash('CTF updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_ctf.html', ctf=ctf)

# Route to display challenges for a specific CTF
@app.route('/ctf/<int:ctf_id>', methods=["GET", "POST"])
@login_required
def view_ctf(ctf_id):

    if request.method == "POST":
        # Method for user submitting answer to the challenge
    
        challenge_id = request.form.get('challenge_id')
        submitted_flag = request.form.get('submitted_flag')

        marked = mark_challenge_completed(current_user.id, challenge_id, submitted_flag)

        if marked == "success":
            # Successfully submitted flag, all correct
            flash('Flag Submitted!', 'success')
        elif marked == "wrong_flag":
            # Successfully submitted flag, all correct
            flash('Wrong flag!', 'error')
        elif marked == "already_submitted":
            # Something went wrong, user already submitted this flag, not correct
            flash('You already submitted this flag!', 'error')
        else:
            # Something went wrong, user already submitted this flag, not correct
            flash('Something went wrong!', 'error')


    challenges = query_db('SELECT * FROM challenge WHERE ctf_id = ?', (ctf_id,))

    name = (query_db("SELECT name FROM ctf WHERE id = ?", (ctf_id,), one=True))['name']

    is_admin = False
    if current_user.is_authenticated:
        is_admin = current_user.is_admin


    statistics = get_ctf_statistics(ctf_id)

    users=[]
    users_temp=[]
    chart_points = []
    chart_challenges = []
    

    #for column in statistics['Total Users Participated'].keys():
    #    print(f"{column}: {statistics['Total Users Participated'][column]}")
    
    for user_id, completed_challenges in statistics["Completed Challenges by User"].items():
        #print(f"User {get_username_by_user_id(user_id)}: {completed_challenges} challenges completed")
        users.append(get_username_by_user_id(user_id))
        chart_challenges.append(completed_challenges)
    
    for user_id, points in statistics["User Points"].items():
        #print(f"User {get_username_by_user_id(user_id)}: {points} points")
        users_temp.append(get_username_by_user_id(user_id))
        chart_points.append(points)

    users_temp_index_map = {value: index for index, value in enumerate(users_temp)}

    chart_points = [chart_points[users_temp_index_map[value]] for value in users]

    return render_template('view_ctf.html', challenges=challenges, ctf_id=ctf_id, is_admin=is_admin, name=name, users=users, chart_points=chart_points, chart_challenges=chart_challenges)

# Route to add a new challenge to a specific CTF
@app.route('/add_challenge/<int:ctf_id>', methods=['GET', 'POST'])
@login_required
def add_challenge(ctf_id):
    if not current_user.is_admin:
        flash("You are not authorized to add challenges.", "danger")
        return redirect(url_for('view_ctf', ctf_id=ctf_id))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        points = int(request.form['points'])
        flag = request.form['flag']  # Get the flag value from the form

        # Insert challenge into the database
        query_db('''
        INSERT INTO challenge (ctf_id, name, description, points, flag)
        VALUES (?, ?, ?, ?, ?)
        ''', (ctf_id, name, description, points, flag))

        flash('Challenge added successfully!', 'success')
        return redirect(url_for('view_ctf', ctf_id=ctf_id))

    return render_template('add_challenge.html', ctf_id=ctf_id)

# Route to edit an existing challenge
@app.route('/edit_challenge/<int:challenge_id>', methods=['GET', 'POST'])
@login_required
def edit_challenge(challenge_id):
    challenge = query_db('SELECT * FROM challenge WHERE id = ?', (challenge_id,), one=True)

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        points = int(request.form['points'])
        flag = request.form['flag']

        # Update challenge details in the database
        query_db('''
        UPDATE challenge SET name = ?, description = ?, points = ?, flag = ?
        WHERE id = ?
        ''', (name, description, points, flag, challenge_id))

        flash('Challenge updated successfully!', 'success')
        return redirect(url_for('view_ctf', ctf_id=challenge['ctf_id']))

    return render_template('edit_challenge.html', challenge=challenge)

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


#  Start the Flask server
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
