from flask import Blueprint, request, session, flash, redirect, url_for, send_file
from flask_login import current_user, login_required
import os, secrets, logging, requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from config import *
from helpers import *

api_bp = Blueprint('api', __name__, url_prefix='/api')

load_dotenv()
blu_api_key = os.getenv('BLU_API_KEY')

@api_bp.route('/totalpoints', methods=['GET'])
def api_get_points():
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /totalpoints with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}
    
    discord_handle = request.args.get('discord_handle')
    if not discord_handle:
        logging.info(f'An API call was made to /totalpoints without discord_handle defined.')
        return {'error': 'Discord handle is required'}, 400
    
    # get user_id from discord_handle
    user_id = get_user_id_by_discord_handle(discord_handle)
    if not user_id:
        logging.info(f'An API call was made to /totalpoints without user_id defined.')
        return {'error': 'No user found for the given Discord handle'}, 404

    challenge_points = get_user_challenge_points(user_id)

    if challenge_points:
        total_points = sum(challenge_points.values())
    else:
        total_points = 0

    logging.info(f'/totalpoints was called, returning discord_handle: {discord_handle}, total_points: {total_points}.')
    return {'discord_handle': discord_handle,
            'total_points': total_points}, 200

# List all CTFs in the database and return dictionary with relevant data for each
@api_bp.route('/listctfs', methods=['GET'])
def api_list_ctfs():
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /listctfs with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}

    ctfs = query_db('SELECT id, name, start_date, end_date FROM ctf ORDER BY id ASC')
    if not ctfs:
        return {'error': 'No CTFs found'}, 404

    return {'ctfs': [dict(ctf) for ctf in ctfs]}, 200

# API create a new CTF
@api_bp.route('/createctf', methods=['POST'])
def api_create_ctf():
    api_key = request.headers.get('X-API-KEY')
    if api_key and api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /createctf with an invalid api_key!')
        return {'error': 'Unauthorized'}, 401

    data = request.get_json()
    name = data.get('name')
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    if not all([name, start_date, end_date]):
        return {'error': 'A required field is missing'}, 400

    query_db('INSERT INTO ctf (name, start_date, end_date) VALUES (?, ?, ?)', (name, start_date, end_date))
    return {'success': True}, 201

@api_bp.route('/challenges', methods=['GET'])
def api_get_challenges():
    #api_key = request.headers.get('X-API-KEY')
    #if not api_key or api_key != blu_api_key:
    #    logging.critical(f'WARNING: An API call was made to /challenges with an invalid api_key!')
    #    return {'success': False, 'error': 'Unauthorized'}
    
    ctf_id = request.args.get('ctf_id')
    if not ctf_id:
        return {'error': 'ctf_id is required'}, 400

    try:
        ctf_id = int(ctf_id)
    except ValueError:
        return {'error': 'Invalid CTF ID format'}, 400

    challenges = query_db('SELECT * FROM challenge WHERE ctf_id = ?', (ctf_id,))
    return {'challenges': [dict(row) for row in challenges]}, 200

@api_bp.route('/createchallenge', methods=['POST'])
def api_create_challenge():
    api_key = request.headers.get('X-API-KEY')
    if api_key and api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /createchallenge with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}, 401

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    points = data.get('points')
    ctf_id = data.get('ctf_id')
    flag = data.get('flag')

    # changed this to check for None in name, description, points, ctf_id instead of the previous if not (name and description and points... etc)
    # this caused an issue wherein, if values were set to 0, the if would be true, and thereby return the error.
    # This *should* be fixed now. -- SGE
    if any(x is None for x in [name, description, points, ctf_id, flag]):
        return {'success': False, 'error': 'A required field is missing'}, 400

    query_db('''
        INSERT INTO challenge (ctf_id, name, description, points, flag)
        VALUES (?, ?, ?, ?, ?)
    ''', (ctf_id, name, description, points, flag))

    return {'success': True, 'message': 'Challenge created successfully'}, 201

# API route that returns the global top 10 users with highest points
@api_bp.route('/leaderboard/global', methods=['GET'])
def api_global_leaderboard():
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /leaderboard/global with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}
    
    leaderboard = query_db('''
        SELECT u.username, SUM(c.points) AS total_points
        FROM users u
        JOIN user_challenges uc ON u.id = uc.user_id
        JOIN challenge c ON uc.challenge_id = c.id
        WHERE uc.completed = 1
        GROUP BY u.id
        ORDER BY total_points DESC
        LIMIT 10
    ''')
    return {'leaderboard': [dict(row) for row in leaderboard]}, 200

# API route to return top 10 users with hightest points for specific CTF
@api_bp.route('/leaderboard/<int:ctf_id>', methods=['GET'])
def api_ctf_leaderboard(ctf_id):
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /leaderboard/{ctf_id} with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}
    
    leaderboard = query_db('''
        SELECT u.username, SUM(c.points) AS total_points
        FROM users u
        JOIN user_challenges uc ON u.id = uc.user_id
        JOIN challenge c ON uc.challenge_id = c.id
        WHERE uc.completed = 1 AND c.ctf_id = ?
        GROUP BY u.id
        ORDER BY total_points DESC
        LIMIT 10
    ''', (ctf_id,))
    return {'leaderboard': [dict(row) for row in leaderboard]}, 200

# generate a token to be used with a discord bot command to link accounts
@api_bp.route('/generate-link-token', methods=['POST'])
@login_required
def generate_link_token():
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401

    token = secrets.token_hex(16)
    user_id = session['user_id']
    expiry_time = datetime.now() + timedelta(minutes=10)

    query_db('INSERT INTO link_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            (user_id, token, expiry_time))

    return {'token': token}, 200

@api_bp.route('/verify-link-token', methods=['POST'])
def verify_link_token():
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /verify-link-token with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}
    
    data = request.get_json()
    token = data.get('token')
    discord_handle = data.get('discord_handle')

    if not token or not discord_handle:
        return {'error': 'Token and Discord handle are required'}, 400

    token_data = query_db('SELECT * FROM link_tokens WHERE token = ?', (token,), one=True)

    if not token_data:
        logging.critical(f'WARNING: An API call was made to /verify-link-token with an invalid token!')
        return {'error': 'Invalid token'}, 400
    
    try:
        expiry_time = datetime.fromisoformat(token_data['expires_at'])
        if datetime.now() > expiry_time:
            query_db('DELETE FROM link_tokens WHERE token = ?', (token,))
            logging.critical(f'WARNING: An API call was made to /verify-link-token with an expired token!')
            return {'error': 'Expired token'}, 400
    except (ValueError, TypeError):
        logging.critical(f'WARNING: An API call was made to /verify-link-token with an invalid token!')
        return {'error': 'Invalid token'}, 400

    user_id = token_data['user_id']
    query_db('UPDATE users SET discord_handle = ? WHERE id = ?', (discord_handle, user_id))

    query_db('DELETE FROM link_tokens WHERE token = ?', (token,))
    return {'success': True}, 200

@api_bp.route('/unlink_discord', methods=['POST'])
@login_required
def unlink_discord():
    try:
        query_db('UPDATE users SET discord_handle = NULL WHERE id = ?', (current_user.id,))
        flash('Discord account successfully unlinked.', 'success')
        logging.info(f'Discord account unlinked for user: {current_user.username} (ID: {current_user.id})')
    except Exception as e:
        logging.error(f'Error unlinking Discord account for user: {current_user.username}. {str(e)}')
        flash('An error occurred while unlinking your Discord account.', 'error')
    return redirect(url_for('profile'))

@api_bp.route('/submitflag', methods=['POST'])
def api_submit_flag():
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /submitflag with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}

    data = request.json
    ctf_id = data.get('ctf_id')
    challenge_id = data.get('challenge_id')
    submitted_flag = data.get('submitted_flag')
    discord_handle = data.get('discord_handle')

    if not all([ctf_id, challenge_id, submitted_flag, discord_handle]):
        return {'success': False, 'error': 'Missing required fields'}, 400

    try:
        user_id = get_user_id_by_discord_handle(discord_handle)
        if not user_id:
            return {'success': False, 'error': 'User ID is required'}, 400

        result = mark_challenge_completed(user_id, challenge_id, submitted_flag)

        if result == 'success':
            return {'success': True}, 200
        elif result == 'wrong_flag':
            return {'success': False, 'error': 'wrong_flag'}, 200
        elif result == 'already_submitted':
            return {'success': False, 'error': 'already_submitted'}, 200
    except Exception as e:
        logging.error(f"Error submitting flag: {e}")
        return {'success': False, 'error': 'Internal server error'}, 500

    return {'success': False, 'error': 'Unexpected error'}, 500

@api_bp.route('/delete_ctf/<int:ctf_id>', methods=['DELETE'])
def api_delete_ctf(ctf_id):
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /delete_ctf/{ctf_id} with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}
    
    if not current_user.is_admin:
        logging.critical(f'WARNING: An API call was made to /delete_ctf/{ctf_id} by a non-admin user!')
        return {"error": "Unauthorized"}, 403

    delete_ctf(ctf_id)
    logging.warning(f'User {current_user.username} deleted a CTF with ID {ctf_id}.')
    return {"success": True}, 200

@api_bp.route('/delete_challenge/<int:challenge_id>', methods=['DELETE'])
def api_delete_challenge(challenge_id):
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /delete_challenge/{challenge_id} with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}
    
    if not current_user.is_admin:
        logging.critical(f'WARNING: An API call was made to /delete_challenge/{challenge_id} by a non-admin user!')
        return {"error": "Unauthorized"}, 403

    delete_challenge(challenge_id)
    logging.warning(f'User {current_user.username} deleted a CTF Challenge with ID {challenge_id}.')
    return {"success": True}, 200

@api_bp.route('/delete_bug_bounty/<int:bounty_id>', methods=['DELETE'])
def api_delete_bug_bounty(bounty_id):
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != blu_api_key:
        logging.critical(f'WARNING: An API call was made to /delete_bug_bounty/{bounty_id} with an invalid api_key!')
        return {'success': False, 'error': 'Unauthorized'}
    
    if not current_user.is_admin:
        logging.critical(f'WARNING: An API call was made to /delete_bug_bounty/{bounty_id} by a non-admin user!')
        return {"error": "Unauthorized"}, 403

    delete_bug_bounty(bounty_id)
    logging.warning(f'User {current_user.username} deleted a Bug Bounty with ID {bounty_id}.')
    return {"success": True}, 200

@api_bp.route('/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
def api_delete_user(user_id):
    # NOT currently allowing deletion of users from external sources (e.g. discord bot)
    # treating user deletion as much more significant than ctf/challenge/bounty deletion
    if not current_user.is_admin:
        logging.critical(f'WARNING: An API call was made to /api_delete_user by a non-admin user!')
        flash("You are not authorized to delete users.", "error")
        return redirect(url_for('dashboard'))

    # Ensure the user exists before attempting to delete
    user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        logging.critical(f'WARNING: {current_user.username} attempted to delete User with ID {user_id}, which does not exist!')
        return {"error": "User not found"}, 404
    
    delete_user(user_id)
    logging.critical(f'USER DELETED! User {current_user.username} deleted a User with ID {user_id}!')
    return {"success": True}, 200

@api_bp.route('/view_logs', methods=['GET'])
@login_required
def api_view_logs():
    if not current_user.is_admin:
        logging.critical(f'WARNING: An API call was made to /view_logs by a non-admin user!')
        flash("You are not authorized to view logs.", "error")
        return redirect(url_for('dashboard'))
    
    try:
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()[-100:] # getting last 100 lines of logfile
        return {'logs': logs}, 200
    except FileNotFoundError:
        return {'error', 'Log file not found'}, 404

@api_bp.route('/download_logs', methods=['GET'])
@login_required
def api_download_logs():
    if not current_user.is_admin:
        logging.critical(f'WARNING: An API call was made to /download_logs by a non-admin user!')
        flash("You are not authorized to download log files.", "error")
        return redirect(url_for('dashboard'))
    
    try:
        logging.warning(f'A log file was downloaded via /download_logs!')
        return send_file(LOG_FILE, as_attachment=True, download_name="server.log")
    except FileNotFoundError:
        return {'error': 'Log file not found'}, 404

@api_bp.route('/update_challenge_order', methods=['POST'])
@login_required
def update_challenge_order():
    if not current_user.is_admin:
        logging.critical('WARNING: An API call was made to /update_challenge_order by a non-admin user!')
        return redirect(url_for('dashboard'))

    data = request.get_json()
    challenge_orders = data.get('challenge_orders')

    if not challenge_orders:
        return {'error': 'Invalid request data'}, 400

    for challenge in challenge_orders:
        query_db('UPDATE challenge SET order_index = ? WHERE id = ?', (challenge['order_index'], challenge['id']))

    return {'success': True, 'message': 'Challenge order updated successfully'}