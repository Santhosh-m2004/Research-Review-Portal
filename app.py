import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from functools import wraps
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from bson.objectid import ObjectId
from bson import errors as bson_errors
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
import cloudinary.api
import urllib.parse

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Flask Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key_change_in_production')

# Cloudinary Configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# MongoDB Atlas connection from .env
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    raise ValueError("⚠️ MONGO_URI is not set in .env file")

client = MongoClient(mongo_uri)
db = client.research_portal
users_collection = db.users
documents_collection = db.documents
notifications_collection = db.notifications
assignments_collection = db.assignments

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or session.get('role') != 'teacher':
            flash('Teacher access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or session.get('role') != 'student':
            flash('Student access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def add_notification(user_id, message, category='info'):
    notification = {
        'user_id': user_id,
        'message': message,
        'category': category,
        'read': False,
        'created_at': datetime.utcnow()
    }
    notifications_collection.insert_one(notification)

def get_inline_view_url(cloudinary_url, filename):
    """
    Generate a Cloudinary URL that forces inline display for supported file types
    """
    # For raw files, we can't force inline display through Cloudinary transformations
    # Instead, we'll rely on the browser's behavior for different file types
    return cloudinary_url

# Create default admin if not exists
def create_default_admin():
    admin_exists = users_collection.find_one({'username': 'admin', 'role': 'admin'})
    if not admin_exists:
        hashed_password = generate_password_hash('admin123')
        admin_user = {
            'username': 'admin',
            'password': hashed_password,
            'email': 'admin@researchportal.com',
            'full_name': 'System Administrator',
            'role': 'admin',
            'created_at': datetime.utcnow(),
            'profile_picture': None
        }
        users_collection.insert_one(admin_user)
        print("Default admin created: username=admin, password=admin123")

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'logged_in' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        full_name = request.form['full_name']
        role = request.form['role']  # Only 'student' or 'teacher' allowed
        
        # Validation
        if not username or not password or not email or not full_name:
            flash('All fields are required.', 'error')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
            
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')
            
        if role not in ['student', 'teacher']:
            flash('Invalid role selected.', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('Username or email already exists.', 'error')
            return render_template('register.html')
        
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Create user document
        user = {
            'username': username,
            'password': hashed_password,
            'email': email,
            'full_name': full_name,
            'role': role,
            'created_at': datetime.utcnow(),
            'profile_picture': None
        }
        
        # Insert user into database
        users_collection.insert_one(user)
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = 'remember_me' in request.form
        
        # Find user in database
        user = users_collection.find_one({'$or': [{'username': username}, {'email': username}]})
        
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user.get('full_name', 'User')
            
            # Set session permanence based on remember me
            session.permanent = remember_me
            
            # Add login notification
            add_notification(session['user_id'], f'Successful login from {request.remote_addr}', 'info')
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/email or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    session.clear()
    flash(f'Goodbye {username}! You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('home'))

@app.route('/home')
def home():
    """Landing page for non-authenticated users"""
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get statistics
    user_stats = {
        'total_users': users_collection.count_documents({}),
        'total_admins': users_collection.count_documents({'role': 'admin'}),
        'total_teachers': users_collection.count_documents({'role': 'teacher'}),
        'total_students': users_collection.count_documents({'role': 'student'})
    }
    
    doc_stats = {
        'total_documents': documents_collection.count_documents({}),
        'documents_with_feedback': documents_collection.count_documents({'feedback': {'$exists': True, '$ne': None}}),
        'documents_pending_feedback': documents_collection.count_documents({'feedback': {'$exists': False}})
    }
    
    # Get recent documents
    recent_documents = list(documents_collection.find().sort('uploaded_at', -1).limit(5))
    for doc in recent_documents:
        doc['id'] = str(doc['_id'])
        # Get student info
        student = users_collection.find_one({'_id': ObjectId(doc['user_id'])})
        doc['student_name'] = student['full_name'] if student else 'Unknown'
        # Generate view URL
        doc['view_url'] = url_for('view_document', doc_id=str(doc['_id']))
    
    # Get all teachers and students for assignment
    teachers = list(users_collection.find({'role': 'teacher'}))
    students = list(users_collection.find({'role': 'student'}))
    
    # Get current assignments
    assignments = list(assignments_collection.find())
    for assignment in assignments:
        assignment['id'] = str(assignment['_id'])
        # Get teacher and student info
        teacher = users_collection.find_one({'_id': ObjectId(assignment['teacher_id'])})
        student = users_collection.find_one({'_id': ObjectId(assignment['student_id'])})
        assignment['teacher_name'] = teacher['full_name'] if teacher else 'Unknown'
        assignment['student_name'] = student['full_name'] if student else 'Unknown'
    
    return render_template('admin_dashboard.html', 
                         user_stats=user_stats,
                         doc_stats=doc_stats,
                         recent_documents=recent_documents,
                         teachers=teachers,
                         students=students,
                         assignments=assignments)

@app.route('/teacher/dashboard')
@login_required
@teacher_required
def teacher_dashboard():
    teacher_id = session['user_id']
    
    # Get assigned students
    assigned_students = list(assignments_collection.find({'teacher_id': teacher_id}))
    student_ids = [assignment['student_id'] for assignment in assigned_students]  # keep as strings
    
    # Get documents from assigned students
    documents = list(documents_collection.find({'user_id': {'$in': student_ids}}).sort('uploaded_at', -1))
    for doc in documents:
        doc['id'] = str(doc['_id'])
        # Get student info
        student = users_collection.find_one({'_id': ObjectId(doc['user_id'])})
        doc['student_name'] = student['full_name'] if student else 'Unknown'
        # Generate view URL
        doc['view_url'] = url_for('view_document', doc_id=str(doc['_id']))
    
    # Get list of assigned students with details
    students_with_details = []
    for assignment in assigned_students:
        student = users_collection.find_one({'_id': ObjectId(assignment['student_id'])})
        if student:
            student['assignment_id'] = str(assignment['_id'])
            students_with_details.append(student)
    
    return render_template('teacher_dashboard.html', 
                         documents=documents,
                         students=students_with_details)

@app.route('/student/dashboard')
@login_required
@student_required
def student_dashboard():
    user_id = session['user_id']
    
    # Get documents
    documents = list(documents_collection.find({'user_id': user_id}).sort('uploaded_at', -1))
    for doc in documents:
        doc['id'] = str(doc['_id'])
        # Generate view URL
        doc['view_url'] = url_for('view_document', doc_id=str(doc['_id']))
    
    # Check if student has an assigned teacher
    assignment = assignments_collection.find_one({'student_id': user_id})
    teacher = None
    if assignment:
        teacher = users_collection.find_one({'_id': ObjectId(assignment['teacher_id'])})
    
    return render_template('student_dashboard.html', 
                         documents=documents,
                         teacher=teacher)

@app.route('/upload', methods=['POST'])
@login_required
@student_required
def upload():
    if 'document_submission' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('student_dashboard'))
    
    file = request.files['document_submission']
    if file and allowed_file(file.filename):
        try:
            # Upload to Cloudinary
            upload_result = cloudinary.uploader.upload(
                file,
                folder="research_papers",
                resource_type="raw",
                use_filename=True,
                unique_filename=True
            )
            
            user_id = session['user_id']
            name = request.form['name']
            paper_name = request.form['paper_name']
            description = request.form.get('description', '')
            
            # Create document in database
            document = {
                'user_id': user_id,
                'name': name,
                'paper_name': paper_name,
                'description': description,
                'document_submission': upload_result['secure_url'],
                'cloudinary_public_id': upload_result['public_id'],
                'original_filename': file.filename,
                'feedback': None,
                'status': 'submitted',
                'uploaded_at': datetime.utcnow(),
                'reviewed_at': None,
                'reviewed_by': None
            }
            
            documents_collection.insert_one(document)
            
            # Add notification
            add_notification(user_id, f'Document "{paper_name}" uploaded successfully', 'success')
            
            flash('Document uploaded successfully.', 'success')
            return redirect(url_for('student_dashboard'))
            
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'error')
            return redirect(url_for('student_dashboard'))
    else:
        flash('Invalid file type. Allowed types: pdf, doc, docx, txt.', 'error')
        return redirect(url_for('student_dashboard'))

@app.route('/feedback/<doc_id>', methods=['POST'])
@login_required
@teacher_required
def feedback(doc_id):
    try:
        feedback_text = request.form['feedback']
        status = request.form.get('status', 'reviewed')
        
        update_data = {
            'feedback': feedback_text,
            'status': status,
            'reviewed_at': datetime.utcnow(),
            'reviewed_by': session['user_id']
        }
        
        result = documents_collection.update_one(
            {'_id': ObjectId(doc_id)},
            {'$set': update_data}
        )
        
        if result.modified_count:
            # Get the document to notify the student
            document = documents_collection.find_one({'_id': ObjectId(doc_id)})
            if document:
                add_notification(
                    document['user_id'], 
                    f'Your document "{document["paper_name"]}" has been reviewed by your teacher', 
                    'info'
                )
            
            flash('Feedback submitted successfully.', 'success')
        else:
            flash('Document not found or no changes made.', 'error')
            
    except bson_errors.InvalidId:
        flash('Invalid document ID.', 'error')
    except Exception as e:
        flash(f'Error submitting feedback: {str(e)}', 'error')
    
    return redirect(url_for('teacher_dashboard'))

@app.route('/assign/teacher', methods=['POST'])
@login_required
@admin_required
def assign_teacher():
    try:
        teacher_id = request.form['teacher_id']
        student_id = request.form['student_id']
        
        # Check if assignment already exists
        existing_assignment = assignments_collection.find_one({
            'teacher_id': teacher_id,
            'student_id': student_id
        })
        
        if existing_assignment:
            flash('This student is already assigned to this teacher.', 'warning')
            return redirect(url_for('admin_dashboard'))
        
        # Create assignment
        assignment = {
            'teacher_id': teacher_id,
            'student_id': student_id,
            'assigned_at': datetime.utcnow(),
            'assigned_by': session['user_id']
        }
        
        assignments_collection.insert_one(assignment)
        
        # Add notification to both teacher and student
        teacher = users_collection.find_one({'_id': ObjectId(teacher_id)})
        student = users_collection.find_one({'_id': ObjectId(student_id)})
        
        if teacher:
            add_notification(
                teacher_id, 
                f'You have been assigned to student {student["full_name"] if student else "Unknown"}', 
                'info'
            )
        
        if student:
            add_notification(
                student_id, 
                f'You have been assigned to teacher {teacher["full_name"] if teacher else "Unknown"}', 
                'info'
            )
        
        flash('Teacher assigned to student successfully.', 'success')
        
    except Exception as e:
        flash(f'Error assigning teacher: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/remove/assignment/<assignment_id>', methods=['POST'])
@login_required
@admin_required
def remove_assignment(assignment_id):
    try:
        assignment = assignments_collection.find_one({'_id': ObjectId(assignment_id)})
        if assignment:
            # Add notification to both teacher and student
            teacher = users_collection.find_one({'_id': ObjectId(assignment['teacher_id'])})
            student = users_collection.find_one({'_id': ObjectId(assignment['student_id'])})
            
            assignments_collection.delete_one({'_id': ObjectId(assignment_id)})
            
            if teacher:
                add_notification(
                    assignment['teacher_id'], 
                    f'Your assignment with student {student["full_name"] if student else "Unknown"} has been removed', 
                    'info'
                )
            
            if student:
                add_notification(
                    assignment['student_id'], 
                    f'Your assignment with teacher {teacher["full_name"] if teacher else "Unknown"} has been removed', 
                    'info'
                )
            
            flash('Assignment removed successfully.', 'success')
        else:
            flash('Assignment not found.', 'error')
            
    except bson_errors.InvalidId:
        flash('Invalid assignment ID.', 'error')
    except Exception as e:
        flash(f'Error removing assignment: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/view_document/<doc_id>')
@login_required
def view_document(doc_id):
    """
    Custom document viewer that redirects to Cloudinary URL with proper headers
    """
    try:
        document = documents_collection.find_one({'_id': ObjectId(doc_id)})
        
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard'))
            
        # Check if user has permission to view this document
        if (document['user_id'] != session['user_id'] and 
            session['role'] not in ['admin', 'teacher']):
            
            # For teachers, check if they're assigned to this student
            if session['role'] == 'teacher':
                assignment = assignments_collection.find_one({
                    'teacher_id': session['user_id'],
                    'student_id': document['user_id']
                })
                if not assignment:
                    flash('You are not authorized to view this document.', 'error')
                    return redirect(url_for('dashboard'))
            else:
                flash('You are not authorized to view this document.', 'error')
                return redirect(url_for('dashboard'))
        
        # Get the Cloudinary URL
        cloudinary_url = document['document_submission']
        
        # Create a simple HTML page that redirects to Cloudinary with proper headers
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>View Document - {document['paper_name']}</title>
            <meta http-equiv="refresh" content="0; url={cloudinary_url}">
            <script>
                window.location.href = '{cloudinary_url}';
            </script>
        </head>
        <body>
            <p>Redirecting to document... If you are not redirected, <a href="{cloudinary_url}">click here</a>.</p>
        </body>
        </html>
        """
        
        return html_content
        
    except bson_errors.InvalidId:
        flash('Invalid document ID.', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error viewing document: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

# Alternative direct view route that uses Cloudinary's transformation
@app.route('/direct_view/<doc_id>')
@login_required
def direct_view(doc_id):
    """
    Direct view route that uses Cloudinary URL without intermediate page
    """
    try:
        document = documents_collection.find_one({'_id': ObjectId(doc_id)})
        
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard'))
            
        # Check permissions (same as view_document)
        if (document['user_id'] != session['user_id'] and 
            session['role'] not in ['admin', 'teacher']):
            
            if session['role'] == 'teacher':
                assignment = assignments_collection.find_one({
                    'teacher_id': session['user_id'],
                    'student_id': document['user_id']
                })
                if not assignment:
                    flash('You are not authorized to view this document.', 'error')
                    return redirect(url_for('dashboard'))
            else:
                flash('You are not authorized to view this document.', 'error')
                return redirect(url_for('dashboard'))
        
        # Redirect directly to Cloudinary URL
        return redirect(document['document_submission'])
        
    except bson_errors.InvalidId:
        flash('Invalid document ID.', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error viewing document: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/profile')
@login_required
def profile():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    # Remove password from user data
    user.pop('password', None)
    
    # For students, get assigned teacher
    teacher = None
    if session['role'] == 'student':
        assignment = assignments_collection.find_one({'student_id': session['user_id']})
        if assignment:
            teacher = users_collection.find_one({'_id': ObjectId(assignment['teacher_id'])})
    
    return render_template('profile.html', user=user, teacher=teacher)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    full_name = request.form['full_name']
    email = request.form['email']
    
    # Check if email is already taken by another user
    existing_user = users_collection.find_one({
        'email': email,
        '_id': {'$ne': ObjectId(session['user_id'])}
    })
    
    if existing_user:
        flash('Email already taken by another user.', 'error')
        return redirect(url_for('profile'))
    
    users_collection.update_one(
        {'_id': ObjectId(session['user_id'])},
        {'$set': {
            'full_name': full_name,
            'email': email
        }}
    )
    
    session['full_name'] = full_name
    flash('Profile updated successfully.', 'success')
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('profile'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('profile'))
    
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user or not check_password_hash(user['password'], current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('profile'))
    
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {'_id': ObjectId(session['user_id'])},
        {'$set': {'password': hashed_password}}
    )
    
    flash('Password changed successfully.', 'success')
    return redirect(url_for('profile'))


@app.route('/delete_document/<doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    try:
        document = documents_collection.find_one({'_id': ObjectId(doc_id)})
        
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard'))
            
        # Check if user owns the document or is admin
        if document['user_id'] != session['user_id'] and session['role'] != 'admin':
            flash('You are not authorized to delete this document.', 'error')
            return redirect(url_for('dashboard'))
        
        # Delete from Cloudinary if public_id exists
        if 'cloudinary_public_id' in document:
            try:
                cloudinary.uploader.destroy(document['cloudinary_public_id'], resource_type="raw")
            except Exception as e:
                print(f"Warning: Could not delete from Cloudinary: {str(e)}")
        
        # Delete from database
        documents_collection.delete_one({'_id': ObjectId(doc_id)})
        
        flash('Document deleted successfully.', 'success')
        
    except bson_errors.InvalidId:
        flash('Invalid document ID.', 'error')
    except Exception as e:
        flash(f'Error deleting document: {str(e)}', 'error')
    
    if session['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif session['role'] == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))
    
@app.route('/notifications', methods=['GET', 'POST'])
@login_required
def notifications():
    user_id = session['user_id']
    
    if request.method == 'POST':
        # Mark all notifications as read
        notifications_collection.update_many(
            {'user_id': user_id, 'read': False},
            {'$set': {'read': True}}
        )
        flash('All notifications marked as read.', 'success')
        return redirect(url_for('notifications'))
    
    # Existing GET method code
    page = request.args.get('page', 1, type=int)
    per_page = 10
    skip = (page - 1) * per_page
    
    # Get notifications with pagination
    notifications_list = list(notifications_collection.find({'user_id': user_id})
                             .sort('created_at', -1)
                             .skip(skip)
                             .limit(per_page))
    
    total_notifications = notifications_collection.count_documents({'user_id': user_id})
    
    # Mark as read (this happens on page load for GET requests)
    notifications_collection.update_many(
        {'user_id': user_id, 'read': False},
        {'$set': {'read': True}}
    )
    
    return render_template('notifications.html',
                         notifications=notifications_list,
                         page=page,
                         per_page=per_page,
                         total_notifications=total_notifications)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum size is 100MB.', 'error')
    return redirect(request.url)

if __name__ == '__main__':
    # Create default admin if not exists
    create_default_admin()
    
    app.run(debug=True)