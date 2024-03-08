from flask import Flask, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = 'db/watchparty.sqlite3'


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def query_db(query, args=(), one=False, commit=False):
    db = get_db()
    cursor = db.execute(query, args)
    if commit:
        db.commit()
    rv = cursor.fetchall()
    cursor.close()
    return (rv[0] if rv else None) if one else rv


def user_from_api_key(api_key):
    user = query_db('SELECT * FROM users WHERE api_key = ?',
                    [api_key], one=True)
    return user

# -------------------------------------- Page Routes --------------------------------------#


@app.route('/api/signup', methods=['POST'])
def signup():
    username = request.json['username']
    password = request.json['password']
    api_key = os.urandom(16).hex()
    hashed_password = generate_password_hash(password)
    try:
        query_db('INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)',
                 [username, hashed_password, api_key], commit=True)
        return jsonify({'api_key': api_key}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400


@app.route('/api/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    user = query_db('SELECT * FROM users WHERE username = ?',
                    [username], one=True)
    if user and check_password_hash(user['password_hash'], password):
        return jsonify({'api_key': user['api_key']}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/channels', methods=['GET'])
def get_channels():
    channels = query_db('SELECT * FROM channels')
    return jsonify([dict(row) for row in channels])


@app.route('/api/messages', methods=['POST'])
def post_message():
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    channel_id = request.json['channel_id']
    content = request.json['content']
    # Assuming replies_to is optional and passed in JSON if needed
    replies_to = request.json.get('replies_to', None)

    query_db('INSERT INTO messages (user_id, channel_id, content, replies_to) VALUES (?, ?, ?, ?)',
             [user['id'], channel_id, content, replies_to], commit=True)
    return jsonify({'success': 'Message posted'}), 201


@app.route('/api/messages/<int:channel_id>', methods=['GET'])
def get_messages(channel_id):
    messages = query_db(
        'SELECT * FROM messages WHERE channel_id = ?', [channel_id])
    return jsonify([dict(row) for row in messages])


@app.route('/api/channels/<int:channel_id>/mark-read', methods=['POST'])
def mark_channel_as_read(channel_id):
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    # Fetch the latest message ID in this channel
    latest_message = query_db('SELECT id FROM messages WHERE channel_id = ? ORDER BY id DESC LIMIT 1',
                              [channel_id], one=True)
    if not latest_message:
        return jsonify({'error': 'No messages in channel or channel does not exist'}), 404

    # Check if there's an existing read status for this user and channel
    existing_status = query_db('SELECT * FROM user_channel_read_status WHERE user_id = ? AND channel_id = ?',
                               [user['id'], channel_id], one=True)

    if existing_status:
        # Update the existing read status
        query_db('UPDATE user_channel_read_status SET last_read_message_id = ? WHERE user_id = ? AND channel_id = ?',
                 [latest_message['id'], user['id'], channel_id], commit=True)
    else:
        # Insert a new read status
        query_db('INSERT INTO user_channel_read_status (user_id, channel_id, last_read_message_id) VALUES (?, ?, ?)',
                 [user['id'], channel_id, latest_message['id']], commit=True)

    return jsonify({'success': 'Channel marked as read'}), 200


@app.route('/api/unread-counts', methods=['GET'])
def get_unread_message_counts():
    api_key = request.headers.get('Authorization')
    user = user_from_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    channels = query_db('SELECT id FROM channels')
    unread_counts = []
    for channel in channels:
        last_read_message = query_db('SELECT last_read_message_id FROM user_channel_read_status WHERE user_id = ? AND channel_id = ?',
                                     [user['id'], channel['id']], one=True)
        last_read_id = last_read_message['last_read_message_id'] if last_read_message else 0
        unread_count = query_db('SELECT COUNT(*) as count FROM messages WHERE channel_id = ? AND id > ?',
                                [channel['id'], last_read_id], one=True)
        unread_counts.append(
            {'channel_id': channel['id'], 'unread_count': unread_count['count']})

    return jsonify(unread_counts), 200
