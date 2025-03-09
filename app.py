from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
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
    is_admin = users[user_id].get('is_admin', False)
    
    if not (user_id == 'organizer' or is_admin):
        flash('Only organizers and admins can add events', 'error')
        return redirect(url_for('event_list'))

    if request.method == 'POST':
        event_id = len(events) + len(pending_events) + 1
        name = request.form['name']
        date_str = request.form['date']
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d')
            new_event = {
                "id": event_id,
                "name": name,
                "date": date,
                "created_by": user_id
            }
            
            # If admin is creating the event, add it directly to events list
            if is_admin:
                new_event["status"] = "approved"
                events.append(new_event)
                flash('Event created successfully!', 'success')
            else:
                # For organizer, add to pending events
                new_event["status"] = "pending"
                pending_events.append(new_event)
                flash('Event added successfully! Waiting for admin approval.', 'info')
            
            return redirect(url_for('event_list'))
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD', 'error')
            return redirect(url_for('add_event'))
    
    return render_template('add_event.html')

@app.route('/add_score', methods=['GET', 'POST'])
@login_required
def add_score():
    if request.method == 'POST':
        team = request.form['team']
        score = int(request.form['score'])
        new_score = {
            "team": team,
            "score": score
        }
        scoreboard.append(new_score)
        # Sort scoreboard by score in descending order
        scoreboard.sort(key=lambda x: x['score'], reverse=True)
        flash('Score added successfully!')
        return redirect(url_for('show_scoreboard'))
    
    return render_template('add_score.html')

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
    event = next((e for e in events if e['id'] == event_id), None)
    if not event:
        event = next((e for e in pending_events if e['id'] == event_id), None)
    
    if not event:
        flash('Event not found', 'error')
        return redirect(url_for('home'))
    
    participants = event_participants.get(event_id, [])
    
    return render_template('event_details.html', 
                         event=event,
                         participants=participants)

@app.route('/register_activity/<int:event_id>')
@login_required
def register_activity(event_id):
    username = session['user_id']
    if username == 'organizer':
        flash('Organizers cannot register for events')
        return redirect(url_for('event_details', event_id=event_id))
    
    if username not in users:
        flash('User not found')
        return redirect(url_for('event_details', event_id=event_id))
    
    event = next((e for e in events if e['id'] == event_id), None)
    if not event:
        flash('Event not found')
        return redirect(url_for('event_list'))
    
    if event_id not in event_participants:
        event_participants[event_id] = []
    
    if username not in event_participants[event_id]:
        event_participants[event_id].append(username)
        if 'activities' not in users[username]:
            users[username]['activities'] = []
        users[username]['activities'].append({
            "id": event_id,
            "name": event['name'],
            "status": "Registered"
        })
        flash('Successfully registered for the event!')
    else:
        flash('Already registered for this event!')
    
    return redirect(url_for('event_details', event_id=event_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        users[username] = {
            'username': username,
            'password': generate_password_hash(password),
            'activities': [],
            'email': '',
            'major': '',
            'year': '',
            'college_id': ''  # Add college ID field
        }
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['user_id'] = username
            
            # Check if user is new (needs to complete profile)
            user_data = users[username]
            if not user_data.get('is_admin') and not user_data.get('is_organizer'):
                if not all([user_data.get('email'), user_data.get('college_id')]):
                    flash('Please complete your profile before continuing', 'info')
                    return redirect(url_for('setup_profile'))
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        
        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))
    
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
    user_id = session.get('user_id')
    is_admin = users[user_id].get('is_admin', False)
    is_organizer = user_id == 'organizer'
    
    if is_admin:
        # Calculate statistics for admin dashboard
        total_events = len(events)
        total_participants = sum(len(participants) for participants in event_participants.values())
        pending_count = len(pending_events)
        total_users = len([u for u in users.values() if not u.get('is_admin') and not u.get('is_organizer')])
        
        # Get recent events (last 5)
        recent_events = sorted(events, key=lambda x: x['date'], reverse=True)[:5]
        for event in recent_events:
            event['participants'] = event_participants.get(event['id'], [])
        
        return render_template('admin_dashboard.html',
                             total_events=total_events,
                             total_participants=total_participants,
                             pending_count=pending_count,
                             total_users=total_users,
                             recent_events=recent_events,
                             pending_events=pending_events[:5])
    
    elif is_organizer:
        # Calculate statistics for organizer dashboard
        my_events = [event for event in events if event.get('created_by') == user_id]
        my_pending = [event for event in pending_events if event.get('created_by') == user_id]
        
        # Calculate statistics
        my_approved_events = len(my_events)
        my_pending_events = len(my_pending)
        total_participants = sum(len(event_participants.get(event['id'], [])) for event in my_events)
        
        # Get recent events created by this organizer
        my_recent_events = sorted(my_events, key=lambda x: x['date'], reverse=True)[:5]
        
        return render_template('organizer_dashboard.html',
                             my_approved_events=my_approved_events,
                             my_pending_events=my_pending_events,
                             total_participants=total_participants,
                             my_recent_events=my_recent_events,
                             my_pending_event_list=my_pending[:5],
                             event_participants=event_participants)
    
    # User dashboard
    current_date = datetime.now()
    
    # Get user's events
    user_events = [
        event for event in events 
        if event['id'] in event_participants and 
        user_id in event_participants[event['id']]
    ]
    
    # Split into past and upcoming events
    past_events = [
        event for event in user_events 
        if event['date'] < current_date
    ]
    upcoming_events = [
        event for event in user_events 
        if event['date'] >= current_date
    ]
    
    # Sort events
    past_events.sort(key=lambda x: x['date'], reverse=True)
    upcoming_events.sort(key=lambda x: x['date'])
    
    return render_template('user_dashboard.html',
                         user=users[user_id],
                         total_participated=len(past_events),
                         upcoming_count=len(upcoming_events),
                         achievements=len(past_events),  # Simple achievement count
                         upcoming_events=upcoming_events[:5],
                         past_events=past_events[:5])

@app.route('/events')
@login_required
def event_list():
    is_organizer = session.get('user_id') == 'organizer'
    is_admin = users[session.get('user_id')].get('is_admin', False)
    current_date = datetime.now()
    
    if is_admin:
        # Show all events for admin
        filtered_events = events
    elif is_organizer:
        # Show all approved events and their pending events for organizer
        organizer_pending = [e for e in pending_events if e['created_by'] == session.get('user_id')]
        filtered_events = events + organizer_pending
    else:
        # Show only approved upcoming events for regular users
        filtered_events = [
            event for event in events 
            if event['date'] >= current_date and event.get('status') == 'approved'
        ]
        filtered_events.sort(key=lambda x: x['date'])

    registered_events = []
    if not is_organizer and not is_admin:
        username = session.get('user_id')
        registered_events = [
            event_id for event_id, participants in event_participants.items()
            if username in participants
        ]
    
    return render_template('events.html', 
                         events=filtered_events,
                         registered_events=registered_events)

@app.route('/scoreboard')
@login_required
def show_scoreboard():
    return render_template('scoreboard.html', scoreboard=scoreboard)

@app.route('/my-activities')
@login_required
def my_activities_list():
    username = session['user_id']
    user_activities = users[username].get('activities', []) if username in users else []
    return render_template('my_activities.html', activities=user_activities)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    username = session['user_id']
    if request.method == 'POST':
        # Update user profile data
        users[username].update({
            'email': request.form.get('email'),
            'major': request.form.get('major'),
            'year': request.form.get('year'),
            'college_id': request.form.get('college_id')
        })
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))

    user_data = users.get(username, {})
    return render_template('profile.html', user=user_data)

@app.route('/upload_profile_image', methods=['POST'])
@login_required
def upload_profile_image():
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    try:
        # The image is already cropped and resized by the client
        filename = f"{session['user_id']}_profile.jpg"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the image directly as it's already processed
        file.save(filepath)
        
        # Update user profile with image path
        users[session['user_id']]['profile_image'] = filename
        
        return jsonify({
            'success': True,
            'image_url': url_for('static', filename=f'uploads/{filename}')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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
    if not users[session.get('user_id')].get('is_admin'):
        flash('Access denied')
        return redirect(url_for('home'))
    return render_template('pending_events.html', pending_events=pending_events)

# New route for handling event approval/rejection
@app.route('/approve_event/<int:event_id>/<action>')
@login_required
def approve_event(event_id, action):
    if not users[session.get('user_id')].get('is_admin'):
        flash('Access denied', 'error')
        return redirect(url_for('home'))
    
    event = next((e for e in pending_events if e['id'] == event_id), None)
    if not event:
        flash('Event not found', 'error')
        return redirect(url_for('pending_events_list'))
    
    if action == 'approve':
        event['status'] = 'approved'
        events.append(event)
        pending_events.remove(event)
        flash('Event approved successfully!', 'success')
    elif action == 'reject':
        event['status'] = 'rejected'
        pending_events.remove(event)
        flash('Event rejected', 'warning')
    
    return redirect(url_for('pending_events_list'))

# New route for initial profile setup
@app.route('/setup_profile', methods=['GET', 'POST'])
@login_required
def setup_profile():
    username = session['user_id']
    user_data = users.get(username, {})
    
    # If profile is already complete, redirect to home
    if all([user_data.get('email'), user_data.get('college_id')]):
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # Update user profile data
        users[username].update({
            'email': request.form.get('email'),
            'major': request.form.get('major'),
            'year': request.form.get('year'),
            'college_id': request.form.get('college_id')
        })
        flash('Profile completed successfully!')
        return redirect(url_for('home'))
    
    return render_template('setup_profile.html', user=user_data)

# Add this after app initialization
@app.context_processor
def utility_processor():
    return {'users': users}

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

if __name__ == '__main__':
    try:
        app.run(debug=True)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received")
        clear_data()

