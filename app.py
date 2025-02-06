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
scoreboard = []
users = {
    'organizer': {
        'username': 'organizer',
        'password': generate_password_hash('organizer'),
        'is_organizer': True,
        'activities': [],
        'email': '',
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
    if session.get('user_id') != 'organizer':
        flash('Only organizers can add events')
        return redirect(url_for('event_list'))

    if request.method == 'POST':
        event_id = len(events) + 1
        name = request.form['name']
        date_str = request.form['date']
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d')
            new_event = {
                "id": event_id,
                "name": name,
                "date": date
            }
            events.append(new_event)
            event_participants[event_id] = []  # Initialize empty participants list
            flash('Event added successfully!')
            return redirect(url_for('event_list'))
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD')
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
        flash('Event not found')
        return redirect(url_for('event_list'))
    
    participants_count = len(event_participants.get(event_id, []))
    is_registered = False
    
    if session.get('user_id') != 'organizer':
        is_registered = session.get('user_id') in event_participants.get(event_id, [])
    
    return render_template('event_details.html',
                         event=event,
                         participants_count=participants_count,
                         is_registered=is_registered)

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
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        
        flash('Invalid username or password')
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
    is_organizer = session.get('user_id') == 'organizer'
    current_date = datetime.now()
    
    # Get upcoming events
    upcoming_events = [
        event for event in events 
        if event['date'] >= current_date
    ]
    upcoming_events.sort(key=lambda x: x['date'])
    
    # Get created events for organizer
    created_events = events if is_organizer else []
    
    registered_events = []
    if not is_organizer:
        username = session.get('user_id')
        registered_events = [
            event_id for event_id, participants in event_participants.items()
            if username in participants
        ]
    
    return render_template('home.html',
                         upcoming_events=upcoming_events,
                         created_events=created_events,
                         registered_events=registered_events)

@app.route('/events')
@login_required
def event_list():
    is_organizer = session.get('user_id') == 'organizer'
    current_date = datetime.now()
    
    if is_organizer:
        # Show all events for organizer
        filtered_events = events
    else:
        # Show only upcoming events for regular users
        filtered_events = [
            event for event in events 
            if event['date'] >= current_date
        ]
        filtered_events.sort(key=lambda x: x['date'])  # Sort by date

    registered_events = []
    if not is_organizer:
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
            'college_id': request.form.get('college_id')  # Add college ID
        })
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))

    user_data = users.get(username, {})
    profile_image = None
    if 'profile_image' in user_data:
        profile_image = url_for('static', filename=f'uploads/{user_data["profile_image"]}')
    return render_template('profile.html', user=user_data, profile_image=profile_image)

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

if __name__ == '__main__':
    try:
        app.run(debug=True)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received")
        clear_data()

