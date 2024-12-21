import sqlite3
from datetime import datetime

from config import *

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
            is_admin INTEGER DEFAULT 0,
            tags TEXT
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

def get_user_ids():
    # Fetches the list of user IDs from the 'users' table.

    query = "SELECT id FROM users"
    result = query_db(query)
    return [row['id'] for row in result]

def get_user_challenge_ids(user_id):
    # Fetches the list of challenge IDs for a given user ID from the 'user_challenges' table

    query = "SELECT challenge_id FROM user_challenges WHERE user_id = ?"
    result = query_db(query, args=(user_id,))
    return [row['challenge_id'] for row in result]

def get_challenge_points(challenge_id):
    # Fetches the points for a given challenge ID from the 'challenge' table.

    query = "SELECT points FROM challenge WHERE id = ?"
    result = query_db(query, args=(challenge_id,))
    return result[0]['points'] if result else None

def get_user_challenge_points(user_id):
    # For a given user ID, fetch the associated challenge IDs and their corresponding points

    challenge_ids = get_user_challenge_ids(user_id)  # Get the list of challenge IDs for the user
    challenge_points = {}

    # For each challenge_id, fetch the corresponding points
    for challenge_id in challenge_ids:
        points = get_challenge_points(challenge_id)
        challenge_points[challenge_id] = points

    return challenge_points

def get_all_user_challenge_points():
    """
    For all users, fetch the challenge points for each challenge associated with the user.
    Returns a dictionary of user IDs as keys, and dictionaries of challenge IDs and points as values.
    """
    user_ids = get_user_ids()  # Get all user IDs
    all_user_challenges_points = {}

    # For each user_id, get the associated challenges and their points
    for user_id in user_ids:
        challenge_points = get_user_challenge_points(user_id)
        all_user_challenges_points[user_id] = challenge_points

    return all_user_challenges_points

def count_user_challenges_completed(user_id):
    query = """
    SELECT COUNT(*) AS count
    FROM user_challenges
    WHERE user_id = ?
    """
    result = query_db(query, [user_id], one=True)
    
    # Extract the count from the result and return it
    if result:
        return result['count']
    else:
        return 0  # If no results, return 0

def get_user_tags(username):
    query = "SELECT tags FROM users WHERE username = ?"
    result = query_db(query, (username,), one=True)
    
    # If a result is found, return the tags value
    if result:
        return result['tags']  # 'tags' is the column name, accessible via the row factory
    return None  # If no result is found, return None