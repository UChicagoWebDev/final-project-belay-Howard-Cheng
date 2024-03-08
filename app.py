import bcrypt
from flask import request
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

DATABASE = 'db/Belay.sqlite3'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False, commit=False):
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchall()
    if commit:
        db.commit()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.errorhandler(404)
def page_not_found(e):
    return 404


def user_from_api_key(api_key):
    if not api_key:
        return None
    return query_db('SELECT * FROM users WHERE api_key = ?', [api_key], one=True)


@app.route('/api/signup', methods=['POST'])
def signup():
    username = request.json.get('username')
    password = request.json.get('password')
    hashed_password = generate_password_hash(password)
    api_key = os.urandom(16).hex()
    try:
        query_db('INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)', [
                 username, hashed_password, api_key], commit=True)
        return jsonify({'api_key': api_key}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400


@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = query_db('SELECT * FROM users WHERE username = ?',
                    [username], one=True)
    if user and check_password_hash(user['password_hash'], password):
        return jsonify({'api_key': user['api_key']}), 200
    return jsonify({'error': 'Invalid username or password'}), 401


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


@app.route('/api/user/change_username', methods=['POST'])
def change_username():
    api_key = request.headers.get('Authorization')
    new_username = request.json.get('new_username')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        query_db('UPDATE users SET username = ? WHERE id = ?',
                 [new_username, user['id']], commit=True)
        return jsonify({'message': 'Username successfully updated'}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400


@app.route('/api/user/change_password', methods=['POST'])
def change_password():
    api_key = request.headers.get('Authorization')
    current_password = request.json.get('current_password')
    new_password = request.json.get('new_password')
    user = user_from_api_key(api_key)
    if not user or not verify_password(user['password_hash'], current_password):
        return jsonify({'error': 'Unauthorized or incorrect password'}), 401
    new_hashed_password = hash_password(new_password)
    query_db('UPDATE users SET password_hash = ? WHERE id = ?',
             [new_hashed_password, user['id']], commit=True)
    return jsonify({'message': 'Password successfully updated'}), 200


@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    user_profile = {
        'username': user['username'],
        # Include other profile details as needed
    }
    return jsonify(user_profile), 200


@app.route('/api/channels', methods=['GET'])
def get_channels():
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    channels = query_db('SELECT * FROM channels')
    return jsonify([{'id': row['id'], 'name': row['name']} for row in channels])


@app.route('/api/messages/<int:channel_id>', methods=['GET'])
def get_messages(channel_id):
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    messages = query_db(
        'SELECT m.*, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE channel_id = ?', [channel_id])
    return jsonify([{'id': row['id'], 'content': row['content'], 'username': row['username']} for row in messages])


@app.route('/api/messages/<int:channel_id>', methods=['POST'])
def post_message(channel_id):
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    content = request.json.get('content')
    replies_to = request.json.get('replies_to', None)  # Optional, for replies

    query_db('INSERT INTO messages (user_id, channel_id, content, replies_to) VALUES (?, ?, ?, ?)',
             [user['id'], channel_id, content, replies_to], commit=True)
    return jsonify({'message': 'Message posted successfully'}), 201


@app.route('/api/channels/<int:channel_id>/mark-read', methods=['POST'])
def mark_channel_as_read(channel_id):
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    last_message_id = request.json.get('last_message_id')

    existing = query_db('SELECT * FROM user_channel_read_status WHERE user_id = ? AND channel_id = ?',
                        [user['id'], channel_id], one=True)
    if existing:
        query_db('UPDATE user_channel_read_status SET last_read_message_id = ? WHERE user_id = ? AND channel_id = ?',
                 [last_message_id, user['id'], channel_id], commit=True)
    else:
        query_db('INSERT INTO user_channel_read_status (user_id, channel_id, last_read_message_id) VALUES (?, ?, ?)',
                 [user['id'], channel_id, last_message_id], commit=True)
    return jsonify({'message': 'Channel marked as read'}), 200


@app.route('/api/user/update', methods=['POST'])
def update_user_details():
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    new_username = request.json.get('new_username')
    new_password = request.json.get('new_password')

    if new_username:
        query_db('UPDATE users SET username = ? WHERE id = ?',
                 [new_username, user['id']], commit=True)
    if new_password:
        hashed_password = generate_password_hash(new_password)
        query_db('UPDATE users SET password_hash = ? WHERE id = ?',
                 [hashed_password, user['id']], commit=True)

    return jsonify({'message': 'User details updated successfully'}), 200


@app.route('/api/unread-counts', methods=['GET'])
def get_unread_message_counts():
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    channels = query_db('SELECT id FROM channels')
    unread_counts = {}
    for channel in channels:
        channel_id = channel['id']
        last_read_info = query_db('SELECT last_read_message_id FROM user_channel_read_status WHERE user_id = ? AND channel_id = ?', [
                                  user['id'], channel_id], one=True)
        last_read_id = last_read_info['last_read_message_id'] if last_read_info else 0
        unread_count = query_db(
            'SELECT COUNT(*) AS count FROM messages WHERE channel_id = ? AND id > ?', [channel_id, last_read_id], one=True)
        unread_counts[channel_id] = unread_count['count']

    return jsonify(unread_counts), 200


@app.route('/api/messages/<int:message_id>/react', methods=['POST'])
def react_to_message(message_id):
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    emoji = request.json.get('emoji')
    if not emoji:
        return jsonify({'error': 'No emoji provided'}), 400

    # Check if the message exists
    if not query_db('SELECT id FROM messages WHERE id = ?', [message_id], one=True):
        return jsonify({'error': 'Message not found'}), 404

    # Add reaction
    try:
        query_db('INSERT INTO reactions (message_id, user_id, emoji) VALUES (?, ?, ?)',
                 [message_id, user['id'], emoji], commit=True)
        return jsonify({'message': 'Reaction added'}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Could not add reaction'}), 500


@app.route('/api/messages/<int:message_id>/reactions', methods=['GET'])
def get_message_reactions(message_id):
    api_key = request.headers.get('Authorization')
    if not user_from_api_key(api_key):
        return jsonify({'error': 'Unauthorized'}), 401

    reactions = query_db(
        'SELECT r.emoji, COUNT(r.id) as count FROM reactions r WHERE r.message_id = ? GROUP BY r.emoji', [message_id])
    if reactions:
        return jsonify({reaction['emoji']: reaction['count'] for reaction in reactions}), 200
    return jsonify({'message': 'No reactions found'}), 404


@app.route('/api/channels/<int:channel_id>/new-messages', methods=['GET'])
def get_new_messages(channel_id):
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    last_message_id = request.args.get('last_message_id', 0, type=int)
    new_messages = query_db(
        'SELECT m.*, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE channel_id = ? AND m.id > ? ORDER BY m.id ASC', [channel_id, last_message_id])

    return jsonify([{'id': row['id'], 'content': row['content'], 'username': row['username'], 'timestamp': row['timestamp']} for row in new_messages])


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/channels/updates', methods=['GET'])
def get_channel_updates():
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401


@app.route('/some-specific-route')
def some_specific_route():
    user_agent = request.headers.get('User-Agent')
    if 'Mobile' in user_agent:
        # Serve mobile-specific content or template
        pass
    else:
        # Serve desktop-specific content or template
        pass


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    if path != "" and os.path.exists("static/" + path):
        return send_from_directory('static', path)
    else:
        return send_from_directory('static', 'index.html')


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True)
