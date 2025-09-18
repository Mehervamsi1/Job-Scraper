# Job Application Tracker with Role-Based Email Updates
# Main Application File: app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import schedule
import time
import threading
from datetime import datetime, timedelta
import json
import os
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Configuration
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'your-email@gmail.com',  # Configure this
    'sender_password': 'your-app-password'    # Use app password for Gmail
}

@dataclass
class JobListing:
    title: str
    company: str
    location: str
    description: str
    url: str
    date_found: str

@dataclass
class UserApplication:
    job_title: str
    company: str
    application_date: str
    status: str  # applied, interview, rejected, accepted
    notes: str = ""

class DatabaseManager:
    def __init__(self):
        self.db_name = 'job_tracker.db'
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            roles TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Job listings table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS job_listings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            company TEXT NOT NULL,
            location TEXT,
            description TEXT,
            url TEXT,
            role_category TEXT,
            date_found TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # User applications table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            job_title TEXT NOT NULL,
            company TEXT NOT NULL,
            application_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'applied',
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Email logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email_type TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_user(self, username, password, email, roles):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)
        
        try:
            cursor.execute('''
            INSERT INTO users (username, password_hash, email, roles)
            VALUES (?, ?, ?, ?)
            ''', (username, password_hash, email, json.dumps(roles)))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def authenticate_user(self, username, password):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, password_hash, email, roles FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            return {
                'id': user[0],
                'username': username,
                'email': user[2],
                'roles': json.loads(user[3])
            }
        return None
    
    def add_job_listing(self, job_listing, role_category):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO job_listings (title, company, location, description, url, role_category)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (job_listing.title, job_listing.company, job_listing.location, 
              job_listing.description, job_listing.url, role_category))
        
        conn.commit()
        conn.close()
    
    def get_recent_jobs(self, role_categories, days=7):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        placeholders = ','.join('?' * len(role_categories))
        cursor.execute(f'''
        SELECT * FROM job_listings 
        WHERE role_category IN ({placeholders})
        AND date_found >= datetime('now', '-{days} days')
        ORDER BY date_found DESC
        ''', role_categories)
        
        jobs = cursor.fetchall()
        conn.close()
        return jobs
    
    def add_user_application(self, user_id, job_title, company, status='applied', notes=''):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO user_applications (user_id, job_title, company, status, notes)
        VALUES (?, ?, ?, ?, ?)
        ''', (user_id, job_title, company, status, notes))
        
        conn.commit()
        conn.close()
    
    def get_user_applications(self, user_id):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT job_title, company, application_date, status, notes
        FROM user_applications 
        WHERE user_id = ?
        ORDER BY application_date DESC
        ''', (user_id,))
        
        applications = cursor.fetchall()
        conn.close()
        return applications
    
    def get_application_stats(self, user_id):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT status, COUNT(*) as count
        FROM user_applications 
        WHERE user_id = ?
        GROUP BY status
        ''', (user_id,))
        
        stats = dict(cursor.fetchall())
        conn.close()
        return stats

class JobScraper:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def scrape_indeed_jobs(self, role, location=''):
        """Scrape jobs from Indeed (simplified example)"""
        jobs = []
        try:
            # This is a simplified example - in production, you'd need to handle Indeed's anti-bot measures
            search_url = f"https://www.indeed.com/jobs?q={role}&l={location}"
            response = requests.get(search_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find job cards (this selector may need updating based on Indeed's current structure)
            job_cards = soup.find_all('div', {'data-tn-component': 'organicJob'})
            
            for card in job_cards[:10]:  # Limit to 10 jobs
                try:
                    title = card.find('a', {'data-tn-element': 'jobTitle'}).text.strip()
                    company = card.find('span', class_='companyName').text.strip()
                    location = card.find('div', class_='companyLocation').text.strip()
                    
                    # Get job URL
                    job_url = 'https://www.indeed.com' + card.find('a')['href']
                    
                    jobs.append(JobListing(
                        title=title,
                        company=company,
                        location=location,
                        description="",  # Would need additional request to get full description
                        url=job_url,
                        date_found=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ))
                except Exception as e:
                    logger.error(f"Error parsing job card: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error scraping Indeed: {e}")
        
        return jobs
    
    def scrape_linkedin_jobs(self, role, location=''):
        """Scrape jobs from LinkedIn (placeholder - requires LinkedIn API or selenium)"""
        # LinkedIn has strong anti-scraping measures
        # In production, you'd use their API or a service like ScrapingBee
        return []
    
    def scrape_jobs_for_roles(self, roles):
        """Scrape jobs for all specified roles"""
        all_jobs = {}
        
        for role in roles:
            logger.info(f"Scraping jobs for role: {role}")
            jobs = []
            
            # Add different job sites
            jobs.extend(self.scrape_indeed_jobs(role))
            jobs.extend(self.scrape_linkedin_jobs(role))
            
            all_jobs[role] = jobs
            
            # Be respectful with requests
            time.sleep(2)
        
        return all_jobs

class EmailNotifier:
    def __init__(self, email_config):
        self.config = email_config
    
    def send_email(self, to_email, subject, body, is_html=False):
        try:
            msg = MimeMultipart()
            msg['From'] = self.config['sender_email']
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MimeText(body, 'html' if is_html else 'plain'))
            
            server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'])
            server.starttls()
            server.login(self.config['sender_email'], self.config['sender_password'])
            
            text = msg.as_string()
            server.sendmail(self.config['sender_email'], to_email, text)
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False
    
    def send_job_update_email(self, user_email, username, jobs_by_role):
        """Send job update email to user"""
        subject = "New Job Opportunities Based on Your Interests"
        
        body = f"""
        <html>
        <body>
        <h2>Hello {username}!</h2>
        <p>Here are the latest job opportunities matching your selected roles:</p>
        """
        
        for role, jobs in jobs_by_role.items():
            if jobs:
                body += f"<h3>{role} Positions:</h3><ul>"
                for job in jobs[:5]:  # Limit to 5 jobs per role
                    body += f"""
                    <li>
                        <strong>{job.title}</strong> at {job.company}<br>
                        Location: {job.location}<br>
                        <a href="{job.url}">View Job</a>
                    </li>
                    """
                body += "</ul>"
        
        body += """
        </body>
        </html>
        """
        
        return self.send_email(user_email, subject, body, is_html=True)

# Initialize components
db = DatabaseManager()
scraper = JobScraper()
emailer = EmailNotifier(EMAIL_CONFIG)

# Flask Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        roles = request.form.getlist('roles')
        
        if db.create_user(username, password, email, roles):
            flash('Registration successful! Please login.')
            return redirect(url_for('index'))
        else:
            flash('Username already exists!')
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = db.authenticate_user(username, password)
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['email'] = user['email']
        session['roles'] = user['roles']
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password!')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    # Get user's applications and stats
    applications = db.get_user_applications(session['user_id'])
    stats = db.get_application_stats(session['user_id'])
    
    return render_template('dashboard.html', 
                         applications=applications, 
                         stats=stats,
                         username=session['username'],
                         roles=session['roles'])

@app.route('/add_application', methods=['POST'])
def add_application():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    job_title = request.form['job_title']
    company = request.form['company']
    status = request.form['status']
    notes = request.form.get('notes', '')
    
    db.add_user_application(session['user_id'], job_title, company, status, notes)
    flash('Application added successfully!')
    
    return redirect(url_for('dashboard'))

@app.route('/update_roles', methods=['POST'])
def update_roles():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    new_roles = request.json.get('roles', [])
    # Update user roles in database (you'll need to implement this method)
    # For now, just update session
    session['roles'] = new_roles
    
    return jsonify({'success': True})

@app.route('/trigger_scraping')
def trigger_scraping():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    # Trigger manual scraping for current user
    threading.Thread(target=scrape_and_notify_user, args=(session['user_id'],)).start()
    flash('Job scraping initiated! You will receive an email with updates.')
    
    return redirect(url_for('dashboard'))

# Background job functions
def scrape_and_notify_user(user_id):
    """Scrape jobs and notify a specific user"""
    try:
        # Get user info
        conn = sqlite3.connect(db.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT username, email, roles FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return
        
        username, email, roles_json = user
        roles = json.loads(roles_json)
        
        # Scrape jobs
        jobs_by_role = scraper.scrape_jobs_for_roles(roles)
        
        # Save jobs to database
        for role, jobs in jobs_by_role.items():
            for job in jobs:
                db.add_job_listing(job, role)
        
        # Send email notification
        emailer.send_job_update_email(email, username, jobs_by_role)
        
    except Exception as e:
        logger.error(f"Error in scrape_and_notify_user: {e}")

def daily_job_scraping():
    """Daily job scraping for all users"""
    try:
        conn = sqlite3.connect(db.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users')
        user_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        for user_id in user_ids:
            scrape_and_notify_user(user_id)
            time.sleep(60)  # Wait 1 minute between users to avoid rate limiting
            
    except Exception as e:
        logger.error(f"Error in daily_job_scraping: {e}")

# Schedule daily job scraping
schedule.every().day.at("09:00").do(daily_job_scraping)

def run_scheduler():
    """Run the job scheduler in a separate thread"""
    while True:
        schedule.run_pending()
        time.sleep(60)

base_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Job Application Tracker</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">Job Tracker</a>
            {% if session.user_id %}
            <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                    <span class="navbar-text">Hello, {{ session.username }}!</span>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
                </li>
            </ul>
            {% endif %}
        </div>
    </nav>
    
    <div class="container mt-4">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

if __name__ == '__main__':
    # Create templates directory and files
    os.makedirs('templates', exist_ok=True)
    
    # Start scheduler in background
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    
    # Run the Flask app
    app.run(debug=True, use_reloader=False)  # use_reloader=False prevents scheduler from running twice