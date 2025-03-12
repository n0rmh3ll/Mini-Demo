from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import psycopg2
from psycopg2 import pool
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from PIL import Image
import atexit
import signal
import sys

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a real secret key in production

# Database connection pool configuration
db_pool = psycopg2.pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    dbname="eventmanagement",
    user="postgres",
    password="1234",
    host="localhost",
    port="5432"
)

def get_db():
    return db_pool.getconn()

def release_db(conn):
    db_pool.putconn(conn)

# Initialize database tables
def init_db():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Create users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL,
                email VARCHAR(120),
                college_id VARCHAR(50),
                major VARCHAR(100),
                year VARCHAR(20),
                is_admin BOOLEAN DEFAULT FALSE,
                is_organizer BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                profile_image VARCHAR(200)
            )
        """)

        # Drop and recreate events table to ensure correct schema
        cur.execute("DROP TABLE IF EXISTS event_participants CASCADE")
        cur.execute("DROP TABLE IF EXISTS events CASCADE")
        
        # Create events table with correct data types
        cur.execute("""
            CREATE TABLE events (
                id SERIAL PRIMARY KEY,
                name VARCHAR(200) NOT NULL,
                date TIMESTAMP NOT NULL,
                created_by VARCHAR(80) REFERENCES users(username),
                status VARCHAR(20) DEFAULT 'pending'
            )
        """)

        # Create event_participants table with correct schema
        cur.execute("""
            CREATE TABLE event_participants (
                event_id INTEGER REFERENCES events(id),
                username VARCHAR(80) REFERENCES users(username),
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (event_id, username)
            )
        """)

        # Check if admin exists
        cur.execute("SELECT username FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            # Insert admin user
            cur.execute("""
                INSERT INTO users (username, password_hash, is_admin, is_organizer, email, college_id)
                VALUES ('admin', %s, TRUE, FALSE, 'admin@example.com', 'ADMIN001')
            """, (generate_password_hash('admin'),))
            print("Admin user created")

        # Check if organizer exists
        cur.execute("SELECT username FROM users WHERE username = 'organizer'")
        if not cur.fetchone():
            # Insert organizer user
            cur.execute("""
                INSERT INTO users (username, password_hash, is_organizer, is_admin, email, college_id)
                VALUES ('organizer', %s, TRUE, FALSE, 'organizer@example.com', 'ORG001')
            """, (generate_password_hash('organizer'),))
            print("Organizer user created")

        conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

def reset_database():
    """Reset the entire database schema"""
    conn = get_db()
    cur = conn.cursor()
    try:
        print("Completely resetting database...")
        # Drop all tables in the correct order
        cur.execute("DROP TABLE IF EXISTS event_participants CASCADE")
        cur.execute("DROP TABLE IF EXISTS events CASCADE")
        cur.execute("DROP TABLE IF EXISTS users CASCADE")
        
        # Create users table
        cur.execute("""
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL,
                email VARCHAR(120),
                college_id VARCHAR(50),
                major VARCHAR(100),
                year VARCHAR(20),
                is_admin BOOLEAN DEFAULT FALSE,
                is_organizer BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                profile_image VARCHAR(200)
            )
        """)
        
        # Create events table
        cur.execute("""
            CREATE TABLE events (
                id SERIAL PRIMARY KEY,
                name VARCHAR(200) NOT NULL,
                date TIMESTAMP NOT NULL,
                created_by VARCHAR(80) REFERENCES users(username),
                status VARCHAR(20) DEFAULT 'pending'
            )
        """)
        
        # Create event_participants table with simple schema
        cur.execute("""
            CREATE TABLE event_participants (
                event_id INTEGER REFERENCES events(id),
                username VARCHAR(80) REFERENCES users(username),
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (event_id, username)
            )
        """)
        
        # Create admin and organizer users
        cur.execute("""
            INSERT INTO users (username, password_hash, is_admin, is_organizer, email, college_id)
            VALUES ('admin', %s, TRUE, FALSE, 'admin@example.com', 'ADMIN001')
        """, (generate_password_hash('admin'),))
        
        cur.execute("""
            INSERT INTO users (username, password_hash, is_admin, is_organizer, email, college_id)
            VALUES ('organizer', %s, TRUE, FALSE, 'organizer@example.com', 'ORG001')
        """, (generate_password_hash('organizer'),))
        
        conn.commit()
        print("Database reset successfully")
    except Exception as e:
        print(f"Error resetting database: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

# Initialize empty data structures
events = []
pending_events = []  # New list for pending events
scoreboard = []
users = {
    'organizer': {
        'username': 'organizer',
        'password': generate_password_hash('organizer'),
        'is_organizer': True,
        'is_admin': False,  # New field
        'is_admin': False,  # New field
        'activities': [],
        'email': '',
        'major': '',
        'year': '',
        'college_id': ''
    },
    'admin': {
        'username': 'admin',
        'password': generate_password_hash('admin'),
        'is_organizer': True,
        'is_admin': True,  # New field
        'activities': [],
        'email': 'admin',
        'major': '',
        'year': '',
        'college_id': ''
    }
}

# Store registered participants for each event
event_participants = {}  # {event_id: [username1, username2, ...]}

# Add these configurations
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_IMAGE_SIZE = (300, 300)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def clear_data(signum=None, frame=None):
    """Clear all data and exit program"""
    print("\nClearing all data...")
    events.clear()
    users.clear()
    event_participants.clear()
    # Reinitialize organizer account
    users['organizer'] = {
        'username': 'organizer',
        'password': generate_password_hash('organizer'),
        'is_organizer': True,
        'is_admin': False,
        'activities': [],
        'email': '',
        'major': '',
        'year': '',
        'college_id': ''
    }
    print("Data cleared successfully!")
    if signum is not None:  # If called by signal handler
        print("Exiting program...")
        sys.exit(0)

# Register the cleanup function for normal termination
atexit.register(clear_data)

# Register signal handlers for Ctrl+C (SIGINT) and SIGTERM
signal.signal(signal.SIGINT, clear_data)
signal.signal(signal.SIGTERM, clear_data)

@app.route('/add_event', methods=['GET', 'POST'])
@login_required
def add_event():
    user_id = session.get('user_id')
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Check if user is admin or organizer
        cur.execute("SELECT is_admin, is_organizer FROM users WHERE username = %s", (user_id,))
        user_data = cur.fetchone()
        if not user_data or not (user_data[0] or user_data[1]):  # not (is_admin or is_organizer)
            flash('Only organizers and admins can add events', 'error')
            return redirect(url_for('event_list'))

        if request.method == 'POST':
            name = request.form['name']
            date_str = request.form['date']
            try:
                date = datetime.strptime(date_str, '%Y-%m-%d')
                status = 'approved' if user_data[0] else 'pending'  # approved if admin
                
                cur.execute("""
                    INSERT INTO events (name, date, created_by, status)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (name, date, user_id, status))
                
                conn.commit()
                flash('Event created successfully!' if status == 'approved' 
                      else 'Event added successfully! Waiting for admin approval.', 'success')
                return redirect(url_for('event_list'))
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD', 'error')
                return redirect(url_for('add_event'))
    except Exception as e:
        conn.rollback()
        flash(f'An error occurred: {str(e)}', 'error')
    finally:
        cur.close()
        release_db(conn)
    
    return render_template('add_event.html')

@app.route('/add_score', methods=['GET', 'POST'])
@login_required
def add_score():
    conn = get_db()
    cur = conn.cursor()
    try:
        if request.method == 'POST':
            team = request.form['team']
            score = int(request.form['score'])
            
            cur.execute("""
                INSERT INTO scoreboard (team, score)
                VALUES (%s, %s)
            """, (team, score))
            conn.commit()
            
            flash('Score added successfully!')
            return redirect(url_for('show_scoreboard'))
        
        return render_template('add_score.html')
    finally:
        cur.close()
        release_db(conn)

@app.route('/event_participants/<int:event_id>')
@login_required
def event_participants_list(event_id):
    if session.get('user_id') != 'organizer':
        flash('Only organizers can view participants')
        return redirect(url_for('event_list'))
    
    event = next((e for e in events if e['id'] == event_id), None)
    if not event:
        flash('Event not found')
        return redirect(url_for('event_list'))
    
    participants = []
    for username in event_participants.get(event_id, []):
        user_data = users.get(username, {})
        participants.append({
            'username': username,
            'email': user_data.get('email', ''),
            'college_id': user_data.get('college_id', ''),
            'major': user_data.get('major', '')
        })
    
    return render_template('event_participants.html', 
                         event=event, 
                         participants=participants)

@app.route('/event/<int:event_id>')
@login_required
def event_details(event_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        # Get event details
        cur.execute("""
            SELECT e.id, e.name, e.date, e.status, e.created_by, u.email as organizer_email
            FROM events e
            LEFT JOIN users u ON e.created_by = u.username
            WHERE e.id = %s
        """, (event_id,))
        event = cur.fetchone()
        
        if not event:
            flash('Event not found', 'error')
            return redirect(url_for('home'))
        
        # Convert to dictionary for easier template access
        event_dict = {
            'id': event[0],
            'name': event[1],
            'date': event[2],
            'status': event[3],
            'created_by': event[4],
            'organizer_email': event[5]
        }
        
        # Get participants
        cur.execute("""
            SELECT u.username, u.email, u.college_id
            FROM event_participants ep
            JOIN users u ON ep.username = u.username
            WHERE ep.event_id = %s
        """, (event_id,))
        participants = cur.fetchall()
        
        # Check if current user is registered
        cur.execute("""
            SELECT COUNT(*) FROM event_participants
            WHERE event_id = %s AND username = %s
        """, (event_id, session.get('user_id')))
        is_registered = cur.fetchone()[0] > 0
        
        return render_template('event_details.html', 
                             event=event_dict,
                             participants=participants,
                             is_registered=is_registered)
    finally:
        cur.close()
        release_db(conn)

@app.route('/register_event/<int:event_id>')
@login_required
def register_event(event_id):
    username = session.get('user_id')
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Debug: Print current user trying to register
        print(f"User '{username}' attempting to register for event {event_id}")
        
        # Check if user is organizer
        cur.execute("SELECT is_organizer FROM users WHERE username = %s", (username,))
        user_data = cur.fetchone()
        if not user_data:
            flash('User not found', 'error')
            return redirect(url_for('event_list'))
            
        if user_data[0]:
            flash('Organizers cannot register for events', 'error')
            return redirect(url_for('event_details', event_id=event_id))
        
        # Check if event exists and is approved
        cur.execute("SELECT id FROM events WHERE id = %s AND status = 'approved'", (event_id,))
        if not cur.fetchone():
            flash('Event not found or not approved', 'error')
            return redirect(url_for('event_list'))
        
        # Extra debug: Check if any constraints might be violated
        print(f"Inserting: event_id={event_id}, username={username}")
        
        # Use a direct insertion approach with minimal columns
        try:
            cur.execute("""
                INSERT INTO event_participants (event_id, username) 
                VALUES (%s, %s)
            """, (event_id, username))
            
            rows_affected = cur.rowcount
            conn.commit()
            
            if rows_affected > 0:
                flash('Successfully registered for the event!', 'success')
            else:
                flash('Registration failed', 'error')
        except psycopg2.IntegrityError as e:
            conn.rollback()
            if "duplicate key" in str(e):
                flash('Already registered for this event!', 'info')
            else:
                flash(f'Database error: {str(e)}', 'error')
        
        return redirect(url_for('event_details', event_id=event_id))
    except Exception as e:
        conn.rollback()
        # More detailed error logging
        import traceback
        print(f"Error in register_event: {str(e)}")
        print(traceback.format_exc())
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('event_details', event_id=event_id))
    finally:
        cur.close()
        release_db(conn)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cur = conn.cursor()
        try:
            # Check if username exists
            cur.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                flash('Username already exists')
                return redirect(url_for('register'))
            
            # Insert new user - using the correct column names from your schema
            cur.execute("""
                INSERT INTO users (username, password_hash)
                VALUES (%s, %s)
            """, (username, generate_password_hash(password)))
            
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash(f'An error occurred: {str(e)}', 'error')
            print(f"Database error: {e}")
        finally:
            cur.close()
            release_db(conn)
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT username, password_hash, is_admin, is_organizer, email, college_id 
                FROM users WHERE username = %s
            """, (username,))
            user_data = cur.fetchone()
            
            if user_data and check_password_hash(user_data[1], password):
                session['user_id'] = username
                
                # Check if user needs to complete profile
                if not (user_data[2] or user_data[3]):  # not admin or organizer
                    if not all([user_data[4], user_data[5]]):  # no email or college_id
                        flash('Please complete your profile before continuing', 'info')
                        return redirect(url_for('setup_profile'))
                
                flash('Logged in successfully!', 'success')
                return redirect(url_for('home'))
            
            flash('Invalid username or password', 'error')
        finally:
            cur.close()
            release_db(conn)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/home')
@login_required
def home():
    conn = get_db()
    cur = conn.cursor()
    try:
        user_id = session.get('user_id')
        
        # Get user data
        cur.execute("""
            SELECT username, is_admin, is_organizer, email, college_id 
            FROM users 
            WHERE username = %s
        """, (user_id,))
        user_data = cur.fetchone()
        
        # Check if user data is None - this should not happen but let's handle it
        if not user_data:
            # User not found in database despite being logged in
            session.clear()  # Clear invalid session
            flash('User account not found. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        # Convert to dictionary for template
        user = {
            'username': user_data[0],
            'is_admin': user_data[1],
            'is_organizer': user_data[2],
            'email': user_data[3],
            'college_id': user_data[4]
        }
        
        is_admin = user_data[1]
        is_organizer = user_data[2]
        
        if is_admin:
            # Admin dashboard stats
            cur.execute("SELECT COUNT(*) FROM events")
            total_events = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM event_participants")
            total_participants = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM events WHERE status = 'pending'")
            pending_count = cur.fetchone()[0]
            
            cur.execute("""
                SELECT COUNT(*) FROM users 
                WHERE NOT is_admin AND NOT is_organizer
            """)
            total_users = cur.fetchone()[0]
            
            # Get recent events and convert to dictionaries
            cur.execute("""
                SELECT e.id, e.name, e.date, e.status, e.created_by, COUNT(ep.event_id) as participant_count
                FROM events e
                LEFT JOIN event_participants ep ON e.id = ep.event_id
                GROUP BY e.id
                ORDER BY e.date DESC
                LIMIT 5
            """)
            recent_events_data = cur.fetchall()
            recent_events = []
            for row in recent_events_data:
                recent_events.append({
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'created_by': row[4],
                    'participant_count': row[5]
                })
            
            # Get pending events for admin dashboard and convert to dictionaries
            cur.execute("""
                SELECT e.id, e.name, e.date, e.status, e.created_by, u.username as organizer_name
                FROM events e
                JOIN users u ON e.created_by = u.username
                WHERE e.status = 'pending'
                ORDER BY e.date ASC
                LIMIT 5
            """)
            pending_events_data = cur.fetchall()
            pending_events = []
            for row in pending_events_data:
                pending_events.append({
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'created_by': row[4],
                    'organizer_name': row[5]
                })
            
            return render_template('admin_dashboard.html',
                                 user=user,
                                 total_events=total_events,
                                 total_participants=total_participants,
                                 pending_count=pending_count,
                                 total_users=total_users,
                                 recent_events=recent_events,
                                 pending_events=pending_events)
        
        elif is_organizer:
            # Organizer dashboard stats
            cur.execute("""
                SELECT COUNT(*) FROM events 
                WHERE created_by = %s AND status = 'approved'
            """, (user_id,))
            approved_count = cur.fetchone()[0]
            
            cur.execute("""
                SELECT COUNT(*) FROM events 
                WHERE created_by = %s AND status = 'pending'
            """, (user_id,))
            pending_count = cur.fetchone()[0]
            
            # Get recent events created by organizer and convert to dictionaries
            cur.execute("""
                SELECT e.id, e.name, e.date, e.status, COUNT(ep.event_id) as participant_count
                FROM events e
                LEFT JOIN event_participants ep ON e.id = ep.event_id
                WHERE e.created_by = %s
                GROUP BY e.id
                ORDER BY e.date DESC
                LIMIT 5
            """, (user_id,))
            recent_events_data = cur.fetchall()
            recent_events = []
            for row in recent_events_data:
                recent_events.append({
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'participant_count': row[4]
                })
            
            return render_template('organizer_dashboard.html',
                                 user=user,
                                 approved_count=approved_count,
                                 pending_count=pending_count,
                                 recent_events=recent_events)
        
        else:
            # User dashboard
            cur.execute("""
                SELECT e.id, e.name, e.date, e.status, e.created_by
                FROM events e
                JOIN event_participants ep ON e.id = ep.event_id
                WHERE ep.username = %s AND e.date < CURRENT_DATE
                ORDER BY e.date DESC
            """, (user_id,))
            past_events_data = cur.fetchall()
            past_events = []
            for row in past_events_data:
                past_events.append({
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'created_by': row[4]
                })
            
            cur.execute("""
                SELECT e.id, e.name, e.date, e.status, e.created_by
                FROM events e
                JOIN event_participants ep ON e.id = ep.event_id
                WHERE ep.username = %s AND e.date >= CURRENT_DATE
                ORDER BY e.date ASC
            """, (user_id,))
            upcoming_events_data = cur.fetchall()
            upcoming_events = []
            for row in upcoming_events_data:
                upcoming_events.append({
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'created_by': row[4]
                })
            
            return render_template('user_dashboard.html',
                                 user=user,
                                 past_events=past_events[:5],
                                 upcoming_events=upcoming_events[:5],
                                 total_participated=len(past_events))
    finally:
        cur.close()
        release_db(conn)

@app.route('/events')
@login_required
def event_list():
    conn = get_db()
    cur = conn.cursor()
    try:
        user_id = session.get('user_id')
        
        # Get user role
        cur.execute("SELECT is_admin, is_organizer FROM users WHERE username = %s", (user_id,))
        user_data = cur.fetchone()
        is_admin = user_data[0] if user_data else False
        is_organizer = user_data[1] if user_data else False
        
        if is_admin:
            # Show all events for admin with proper date handling
            cur.execute("""
                SELECT e.id, 
                       e.name, 
                       e.date::timestamp, 
                       e.status, 
                       e.created_by,
                       u.email as organizer_email
                FROM events e
                LEFT JOIN users u ON e.created_by = u.username
                ORDER BY e.date
            """)
            # Convert to list of dictionaries with datetime objects
            events = [
                {
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'created_by': row[4],
                    'organizer_email': row[5]
                }
                for row in cur.fetchall()
            ]
        elif is_organizer:
            # Show approved events and organizer's pending events
            cur.execute("""
                SELECT e.id, 
                       e.name, 
                       e.date::timestamp, 
                       e.status, 
                       e.created_by
                FROM events e
                WHERE e.status = 'approved' OR e.created_by = %s
                ORDER BY e.date
            """, (user_id,))
            events = [
                {
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'created_by': row[4]
                }
                for row in cur.fetchall()
            ]
        else:
            # Show only approved upcoming events
            cur.execute("""
                SELECT e.id, 
                       e.name, 
                       e.date::timestamp, 
                       e.status, 
                       e.created_by
                FROM events e
                WHERE e.status = 'approved' AND e.date >= CURRENT_DATE
                ORDER BY e.date
            """)
            events = [
                {
                    'id': row[0],
                    'name': row[1],
                    'date': row[2],
                    'status': row[3],
                    'created_by': row[4]
                }
                for row in cur.fetchall()
            ]
        
        # Get registered events for user
        if not is_organizer and not is_admin:
            cur.execute("""
                SELECT event_id FROM event_participants 
                WHERE username = %s
            """, (user_id,))
            registered_events = [r[0] for r in cur.fetchall()]
        else:
            registered_events = []
        
        return render_template('events.html', 
                             events=events,
                             registered_events=registered_events)
    finally:
        cur.close()
        release_db(conn)

@app.route('/scoreboard')
@login_required
def show_scoreboard():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT team, score, timestamp
            FROM scoreboard
            ORDER BY score DESC
        """)
        scoreboard = cur.fetchall()
        return render_template('scoreboard.html', scoreboard=scoreboard)
    finally:
        cur.close()
        release_db(conn)

@app.route('/my-activities')
@login_required
def my_activities_list():
    username = session['user_id']
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT e.id, e.name, e.date, e.status, ep.registration_date
            FROM events e
            JOIN event_participants ep ON e.id = ep.event_id
            WHERE ep.username = %s
            ORDER BY e.date DESC
        """, (username,))
        activities = cur.fetchall()
        
        return render_template('my_activities.html', activities=activities)
    finally:
        cur.close()
        release_db(conn)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    username = session['user_id']
    conn = get_db()
    cur = conn.cursor()
    
    try:
        if request.method == 'POST':
            # Update user profile data
            cur.execute("""
                UPDATE users 
                SET email = %s, major = %s, year = %s, college_id = %s
                WHERE username = %s
            """, (
                request.form.get('email'),
                request.form.get('major'),
                request.form.get('year'),
                request.form.get('college_id'),
                username
            ))
            conn.commit()
            flash('Profile updated successfully!')
            return redirect(url_for('profile'))

        # Get user data
        cur.execute("""
            SELECT username, email, major, year, college_id, profile_image
            FROM users
            WHERE username = %s
        """, (username,))
        user_data = cur.fetchone()
        
        return render_template('profile.html', user=user_data)
    finally:
        cur.close()
        release_db(conn)

@app.route('/upload_profile_image', methods=['POST'])
@login_required
def upload_profile_image():
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        if file and allowed_file(file.filename):
            filename = f"{session['user_id']}_profile.jpg"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Update database with new image path
            cur.execute("""
                UPDATE users 
                SET profile_image = %s
                WHERE username = %s
            """, (filename, session['user_id']))
            conn.commit()
            
            return jsonify({
                'success': True,
                'image_url': url_for('static', filename=f'uploads/{filename}')
            })
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cur.close()
        release_db(conn)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/dashboard')
@login_required
def dashboard():
    total_events = len(events)
    total_participants = sum(len(participants) for participants in event_participants.values())
    user_registrations = 0
    
    if session.get('user_id') != 'organizer':
        username = session.get('user_id')
        user_registrations = len([
            event_id for event_id, participants in event_participants.items()
            if username in participants
        ])
    
    # Get 5 most recent events
    recent_events = sorted(events, key=lambda x: x['date'], reverse=True)[:5]
    for event in recent_events:
        event['participants'] = event_participants.get(event['id'], [])
    
    return render_template('dashboard.html',
                         total_events=total_events,
                         total_participants=total_participants,
                         user_registrations=user_registrations,
                         recent_events=recent_events)

# New route for admin to manage pending events
@app.route('/pending_events')
@login_required
def pending_events_list():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Check if user is admin
        cur.execute("SELECT is_admin FROM users WHERE username = %s", (session.get('user_id'),))
        is_admin = cur.fetchone()[0]
        
        if not is_admin:
            flash('Access denied')
            return redirect(url_for('home'))
        
        # Get pending events - fix the JOIN condition with type cast
        cur.execute("""
            SELECT e.id, e.name, e.date, e.created_by, u.email 
            FROM events e 
            LEFT JOIN users u ON e.created_by::varchar = u.username
            WHERE e.status = 'pending'
            ORDER BY e.date
        """)
        pending_events = cur.fetchall()
        
        return render_template('pending_events.html', pending_events=pending_events)
    finally:
        cur.close()
        release_db(conn)

# New route for handling event approval/rejection
@app.route('/approve_event/<int:event_id>/<action>')
@login_required
def approve_event(event_id, action):
    conn = get_db()
    cur = conn.cursor()
    try:
        # Check if user is admin
        cur.execute("SELECT is_admin FROM users WHERE username = %s", (session.get('user_id'),))
        if not cur.fetchone()[0]:
            flash('Access denied', 'error')
            return redirect(url_for('home'))
        
        if action == 'approve':
            cur.execute("""
                UPDATE events 
                SET status = 'approved' 
                WHERE id = %s
            """, (event_id,))
            flash('Event approved successfully!', 'success')
        elif action == 'reject':
            cur.execute("""
                UPDATE events 
                SET status = 'rejected' 
                WHERE id = %s
            """, (event_id,))
            flash('Event rejected', 'warning')
        
        conn.commit()
        return redirect(url_for('pending_events_list'))
    finally:
        cur.close()
        release_db(conn)

# New route for initial profile setup
@app.route('/setup_profile', methods=['GET', 'POST'])
@login_required
def setup_profile():
    username = session['user_id']
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Get user data from database
        cur.execute("""
            SELECT username, email, college_id, major, year
            FROM users
            WHERE username = %s
        """, (username,))
        user_data = cur.fetchone()
        
        # If profile is already complete, redirect to home
        if user_data and all([user_data[1], user_data[2]]):  # email and college_id
            return redirect(url_for('home'))
        
        if request.method == 'POST':
            # Update user profile data
            cur.execute("""
                UPDATE users 
                SET email = %s, major = %s, year = %s, college_id = %s
                WHERE username = %s
            """, (
                request.form.get('email'),
                request.form.get('major'),
                request.form.get('year'),
                request.form.get('college_id'),
                username
            ))
            conn.commit()
            flash('Profile completed successfully!')
            return redirect(url_for('home'))
        
        # Convert tuple to dictionary for template
        user_dict = {
            'username': user_data[0] if user_data else username,
            'email': user_data[1] if user_data else '',
            'college_id': user_data[2] if user_data else '',
            'major': user_data[3] if user_data else '',
            'year': user_data[4] if user_data else ''
        }
        
        return render_template('setup_profile.html', user=user_dict)
    finally:
        cur.close()
        release_db(conn)

# Update the context processor to provide all necessary variables
@app.context_processor
def utility_processor():
    def get_user_info(username):
        if not username:
            return None
        
        # First try to get from database
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT username, is_admin, is_organizer, email, college_id, major, year
                FROM users
                WHERE username = %s
            """, (username,))
            user_data = cur.fetchone()
            
            if user_data:
                # Create a dictionary that mimics the old structure
                return {
                    'username': user_data[0],
                    'is_admin': user_data[1],
                    'is_organizer': user_data[2],
                    'email': user_data[3] or '',
                    'college_id': user_data[4] or '',
                    'major': user_data[5] or '',
                    'year': user_data[6] or '',
                    'get': lambda x: user_data[1] if x == 'is_admin' else (user_data[2] if x == 'is_organizer' else None)
                }
            return None
        finally:
            cur.close()
            release_db(conn)
    
    # Get current user info
    current_user_info = get_user_info(session.get('user_id'))
    
    # Create a users dictionary that won't fail on lookup
    users_dict = {}
    if session.get('user_id'):
        users_dict[session.get('user_id')] = current_user_info or {'get': lambda x: None}
    
    return {
        'get_user_info': get_user_info,
        'current_user': current_user_info,
        'users': users_dict
    }

@app.route('/calendar')
@login_required
def event_calendar():
    # Get all events for the calendar
    calendar_events = []
    user_id = session.get('user_id')
    is_admin = users[user_id].get('is_admin', False)
    is_organizer = user_id == 'organizer'
    
    if is_admin:
        # Admin sees all events
        calendar_events = events + pending_events
    elif is_organizer:
        # Organizer sees their events and approved events
        calendar_events = [
            event for event in events + pending_events
            if event.get('created_by') == user_id or event.get('status') == 'approved'
        ]
    else:
        # Regular users see only approved events
        calendar_events = [
            event for event in events
            if event.get('status') == 'approved'
        ]
    
    return render_template('event_calendar.html', events=calendar_events)

# Clean up database connections when the application exits
@atexit.register
def cleanup():
    if db_pool:
        db_pool.closeall()

# Add this function to check the database schema
def check_db_schema():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Check if users table exists and its structure
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users'
        """)
        columns = [col[0] for col in cur.fetchall()]
        print("Users table columns:", columns)
        
        if 'password' not in columns:
            print("Password column missing, recreating users table...")
            # Drop and recreate the users table
            cur.execute("DROP TABLE IF EXISTS event_participants CASCADE")
            cur.execute("DROP TABLE IF EXISTS events CASCADE")
            cur.execute("DROP TABLE IF EXISTS users CASCADE")
            
            # Recreate tables
            init_db()
            print("Database schema recreated.")
        
        conn.commit()
    except Exception as e:
        print(f"Error checking schema: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

def fix_users_table():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Check if password column exists
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'password'
        """)
        if not cur.fetchone():
            print("Adding missing password column to users table...")
            # Add the missing column
            cur.execute("""
                ALTER TABLE users 
                ADD COLUMN password VARCHAR(200) NOT NULL DEFAULT 'temp_password'
            """)
            conn.commit()
            print("Password column added successfully.")
        else:
            print("Password column already exists.")
    except Exception as e:
        print(f"Error fixing users table: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

def check_event_participants_table():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Check the structure of event_participants table
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'event_participants'
        """)
        columns = [col[0] for col in cur.fetchall()]
        print("Event participants table columns:", columns)
        
        # If username column doesn't exist, add it
        if 'username' not in columns:
            print("Username column missing in event_participants, adding it...")
            cur.execute("""
                ALTER TABLE event_participants 
                ADD COLUMN username VARCHAR(80) REFERENCES users(username)
            """)
            conn.commit()
            print("Username column added successfully.")
    except Exception as e:
        print(f"Error checking event_participants table: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

# Now, let's reset the admin and organizer accounts with fresh passwords
def reset_admin_organizer():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Reset admin password
        admin_password = generate_password_hash('admin')
        cur.execute("""
            UPDATE users 
            SET password_hash = %s, is_admin = TRUE
            WHERE username = 'admin'
        """, (admin_password,))
        
        # Reset organizer password
        organizer_password = generate_password_hash('organizer')
        cur.execute("""
            UPDATE users 
            SET password_hash = %s, is_organizer = TRUE
            WHERE username = 'organizer'
        """, (organizer_password,))
        
        # If they don't exist, create them
        cur.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO users (username, password_hash, is_admin, is_organizer, email, college_id)
                VALUES ('admin', %s, TRUE, FALSE, 'admin@example.com', 'ADMIN001')
            """, (admin_password,))
        
        cur.execute("SELECT COUNT(*) FROM users WHERE username = 'organizer'")
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO users (username, password_hash, is_organizer, is_admin, email, college_id)
                VALUES ('organizer', %s, TRUE, FALSE, 'organizer@example.com', 'ORG001')
            """, (organizer_password,))
        
        conn.commit()
        print("Admin and organizer accounts reset successfully")
    except Exception as e:
        print(f"Error resetting admin/organizer: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

# First, let's check the events table structure
def check_events_table():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Check the structure of events table
        cur.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'events'
        """)
        columns = cur.fetchall()
        print("Events table columns:", columns)
        
        # Check if created_by is integer
        cur.execute("""
            SELECT data_type 
            FROM information_schema.columns 
            WHERE table_name = 'events' AND column_name = 'created_by'
        """)
        data_type = cur.fetchone()[0]
        
        if data_type == 'integer':
            print("Altering created_by column to varchar...")
            # Alter the column type
            cur.execute("""
                ALTER TABLE events 
                ALTER COLUMN created_by TYPE VARCHAR(80)
            """)
            conn.commit()
            print("Column type changed successfully.")
    except Exception as e:
        print(f"Error checking events table: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

# First, update the events table schema
def fix_events_table():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Drop the foreign key constraint if it exists
        cur.execute("""
            DO $$ 
            BEGIN 
                IF EXISTS (
                    SELECT 1 FROM information_schema.table_constraints 
                    WHERE constraint_name = 'events_created_by_fkey'
                ) THEN
                    ALTER TABLE events DROP CONSTRAINT events_created_by_fkey;
                END IF;
            END $$;
        """)
        
        # Alter the created_by column to be varchar
        cur.execute("""
            ALTER TABLE events 
            ALTER COLUMN created_by TYPE VARCHAR(80);
            
            -- Add back the foreign key constraint
            ALTER TABLE events 
            ADD CONSTRAINT events_created_by_fkey 
            FOREIGN KEY (created_by) REFERENCES users(username);
        """)
        
        conn.commit()
        print("Events table updated successfully")
    except Exception as e:
        print(f"Error updating events table: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

# Now update the create_event route
@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    conn = get_db()
    cur = conn.cursor()
    try:
        # Check if user is admin or organizer
        cur.execute("""
            SELECT is_admin, is_organizer 
            FROM users 
            WHERE username = %s
        """, (session.get('user_id'),))
        user_data = cur.fetchone()
        
        if not user_data or not (user_data[0] or user_data[1]):
            flash('Access denied')
            return redirect(url_for('home'))
        
        if request.method == 'POST':
            name = request.form['name']
            date = request.form['date']
            created_by = session.get('user_id')
            
            # Insert the event with created_by as varchar
            cur.execute("""
                INSERT INTO events (name, date, created_by, status)
                VALUES (%s, %s::timestamp, %s, %s)
            """, (
                name, 
                date, 
                created_by,
                'approved' if user_data[0] else 'pending'  # Auto-approve if admin
            ))
            
            conn.commit()
            flash('Event created successfully!')
            return redirect(url_for('event_list'))
        
        return render_template('create_event.html')
    except Exception as e:
        conn.rollback()
        flash(f'An error occurred: {str(e)}')
        return redirect(url_for('event_list'))
    finally:
        cur.close()
        release_db(conn)

# Call this function when starting the app
if __name__ == '__main__':
    reset_database()  # Reset the entire database
    try:
        app.run(debug=True)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received")

def check_table_schema(table_name):
    """Check and print the schema of a table"""
    conn = get_db()
    cur = conn.cursor()
    try:
        # Get table columns and their data types
        cur.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = %s
            ORDER BY ordinal_position
        """, (table_name,))
        columns = cur.fetchall()
        
        print(f"\nSchema for table '{table_name}':")
        for col in columns:
            print(f"  {col[0]}: {col[1]} (Nullable: {col[2]})")
        
        # Get primary key info
        cur.execute("""
            SELECT c.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.constraint_column_usage AS ccu USING (constraint_schema, constraint_name)
            JOIN information_schema.columns AS c ON c.table_schema = tc.constraint_schema
                AND tc.table_name = c.table_name AND ccu.column_name = c.column_name
            WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_name = %s
        """, (table_name,))
        pks = cur.fetchall()
        
        if pks:
            print(f"  Primary key: {', '.join(pk[0] for pk in pks)}")
        
        # Print sample data
        cur.execute(f"SELECT * FROM {table_name} LIMIT 5")
        data = cur.fetchall()
        if data:
            print(f"  Sample data: {data}")
        
        return columns
    except Exception as e:
        print(f"Error checking schema: {e}")
        return None
    finally:
        cur.close()
        release_db(conn)

def reset_event_participants_table():
    """Completely recreate the event_participants table"""
    conn = get_db()
    cur = conn.cursor()
    try:
        # Drop the table completely
        cur.execute("DROP TABLE IF EXISTS event_participants CASCADE")
        
        # Create event_participants table with explicit column names
        cur.execute("""
            CREATE TABLE event_participants (
                event_id INTEGER REFERENCES events(id),
                username VARCHAR(80) REFERENCES users(username),
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (event_id, username)
            )
        """)
        
        conn.commit()
        print("Event participants table reset successfully")
    except Exception as e:
        print(f"Error resetting table: {e}")
        conn.rollback()
    finally:
        cur.close()
        release_db(conn)

