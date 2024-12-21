from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory, Blueprint
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

from helpers import *

ctf_bp = Blueprint('ctf', __name__)

# CTFs Landing page
@ctf_bp.route('/ctf')
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
@ctf_bp.route('/create_ctf', methods=['GET', 'POST'])
@login_required
def create_ctf():

    if not current_user.is_admin:
        flash("You are not authorized to create CTFs.", "error")
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
        return redirect(url_for('ctf.list_ctfs'))

    return render_template('create_ctf.html')

# Route to edit an existing CTF
@ctf_bp.route('/edit_ctf/<int:ctf_id>', methods=['GET', 'POST'])
@login_required
def edit_ctf(ctf_id):

    if not current_user.is_admin:
        flash("You are not authorized to create CTFs.", "error")
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
@ctf_bp.route('/ctf/<int:ctf_id>', methods=["GET", "POST"])
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
@ctf_bp.route('/add_challenge/<int:ctf_id>', methods=['GET', 'POST'])
@login_required
def add_challenge(ctf_id):
    if not current_user.is_admin:
        flash("You are not authorized to add challenges.", "error")
        return redirect(url_for('ctf.view_ctf', ctf_id=ctf_id))

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
        return redirect(url_for('ctf.view_ctf', ctf_id=ctf_id))

    return render_template('add_challenge.html', ctf_id=ctf_id)

# Route to edit an existing challenge
@ctf_bp.route('/edit_challenge/<int:challenge_id>', methods=['GET', 'POST'])
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
        return redirect(url_for('ctf.view_ctf', ctf_id=challenge['ctf_id']))

    return render_template('edit_challenge.html', challenge=challenge)
