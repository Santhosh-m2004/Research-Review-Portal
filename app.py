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

app = Flask(__name__)
app.config['SECRET_KEY'] = "537a8f91370423ceb37ab9b8496da4fd035e59e47afd33f635e2fb376f736860"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# MongoDB Atlas connection
client = MongoClient("mongodb+srv://dbUser:Santu%4012345@cluster0.75o1h.mongodb.net/research_portal?retryWrites=true&w=majority&appName=Cluster0")
db = client.research_portal
users_collection = db.users
documents_collection = db.documents
notifications_collection = db.notifications

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
            return redirect(url_for('user_dashboard'))
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'logged_in' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('user_dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        full_name = request.form['full_name']
        role = request.form['role']
        
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
        return redirect(url_for('user_dashboard'))
        
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
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username/email or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    session.clear()
    flash(f'Goodbye {username}! You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'logged_in' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

# In your dashboard routes, modify the document retrieval to include the string ID
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if session['role'] != 'user':
        return redirect(url_for('admin_dashboard'))
    
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    per_page = 10
    skip = (page - 1) * per_page
    
    # Get documents with pagination and convert ObjectId to string
    documents = list(documents_collection.find({'user_id': user_id}).sort('uploaded_at', -1).skip(skip).limit(per_page))
    
    # Add string representation of _id for template usage
    for doc in documents:
        doc['id'] = str(doc['_id'])
    
    total_documents = documents_collection.count_documents({'user_id': user_id})
    
    # Get unread notifications
    unread_notifications = notifications_collection.count_documents({
        'user_id': user_id,
        'read': False
    })
    
    return render_template('user_dashboard.html', 
                         documents=documents,
                         page=page,
                         per_page=per_page,
                         total_documents=total_documents,
                         unread_notifications=unread_notifications)

# Do the same for admin_dashboard
@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '')
    per_page = 10
    skip = (page - 1) * per_page
    
    # Build query for search
    query = {}
    if search_query:
        query['$or'] = [
            {'name': {'$regex': search_query, '$options': 'i'}},
            {'paper_name': {'$regex': search_query, '$options': 'i'}},
            {'feedback': {'$regex': search_query, '$options': 'i'}}
        ]
    
    # Get documents with pagination and search
    documents = list(documents_collection.find(query).sort('uploaded_at', -1).skip(skip).limit(per_page))
    
    # Add string representation of _id for template usage
    for doc in documents:
        doc['id'] = str(doc['_id'])
    
    total_documents = documents_collection.count_documents(query)
    
    # Get user statistics
    user_stats = {
        'total_users': users_collection.count_documents({}),
        'total_admins': users_collection.count_documents({'role': 'admin'}),
        'total_regular_users': users_collection.count_documents({'role': 'user'})
    }
    
    # Get document statistics
    doc_stats = {
        'total_documents': documents_collection.count_documents({}),
        'documents_with_feedback': documents_collection.count_documents({'feedback': {'$exists': True, '$ne': None}}),
        'documents_pending_feedback': documents_collection.count_documents({'feedback': {'$exists': False}})
    }
    
    return render_template('admin_dashboard.html', 
                         documents=documents,
                         page=page,
                         per_page=per_page,
                         total_documents=total_documents,
                         search_query=search_query,
                         user_stats=user_stats,
                         doc_stats=doc_stats)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if session['role'] != 'user':
        flash('Only regular users can upload documents.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if 'document_submission' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('user_dashboard'))
    
    file = request.files['document_submission']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Add unique identifier to avoid filename conflicts
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
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
            'document_submission': unique_filename,
            'original_filename': filename,
            'feedback': None,
            'status': 'submitted',
            'uploaded_at': datetime.utcnow(),
            'reviewed_at': None
        }
        
        documents_collection.insert_one(document)
        
        # Add notification
        add_notification(user_id, f'Document "{paper_name}" uploaded successfully', 'success')
        
        flash('Document uploaded successfully.', 'success')
        return redirect(url_for('user_dashboard'))
    else:
        flash('Invalid file type. Allowed types: pdf, doc, docx, txt.', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/feedback/<doc_id>', methods=['POST'])
@login_required
@admin_required
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
            # Get the document to notify the user
            document = documents_collection.find_one({'_id': ObjectId(doc_id)})
            if document:
                add_notification(
                    document['user_id'], 
                    f'Your document "{document["paper_name"]}" has been reviewed', 
                    'info'
                )
            
            flash('Feedback submitted successfully.', 'success')
        else:
            flash('Document not found or no changes made.', 'error')
            
    except bson_errors.InvalidId:
        flash('Invalid document ID.', 'error')
    except Exception as e:
        flash(f'Error submitting feedback: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/profile')
@login_required
def profile():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    # Remove password from user data
    user.pop('password', None)
    
    return render_template('profile.html', user=user)

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

@app.route('/notifications')
@login_required
def notifications():
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    per_page = 10
    skip = (page - 1) * per_page
    
    # Get notifications with pagination
    notifications_list = list(notifications_collection.find({'user_id': user_id})
                             .sort('created_at', -1)
                             .skip(skip)
                             .limit(per_page))
    
    total_notifications = notifications_collection.count_documents({'user_id': user_id})
    
    # Mark as read
    notifications_collection.update_many(
        {'user_id': user_id, 'read': False},
        {'$set': {'read': True}}
    )
    
    return render_template('notifications.html',
                         notifications=notifications_list,
                         page=page,
                         per_page=per_page,
                         total_notifications=total_notifications)

@app.route('/delete_document/<doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    try:
        document = documents_collection.find_one({'_id': ObjectId(doc_id)})
        
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('user_dashboard'))
            
        # Check if user owns the document or is admin
        if document['user_id'] != session['user_id'] and session['role'] != 'admin':
            flash('You are not authorized to delete this document.', 'error')
            return redirect(url_for('user_dashboard'))
        
        # Delete the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['document_submission'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete from database
        documents_collection.delete_one({'_id': ObjectId(doc_id)})
        
        flash('Document deleted successfully.', 'success')
        
    except bson_errors.InvalidId:
        flash('Invalid document ID.', 'error')
    except Exception as e:
        flash(f'Error deleting document: {str(e)}', 'error')
    
    if session['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(request.url)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    skip = (page - 1) * per_page
    
    # Get users with pagination
    users = list(users_collection.find().sort('created_at', -1).skip(skip).limit(per_page))
    total_users = users_collection.count_documents({})
    
    return render_template('admin_users.html', 
                         users=users,
                         page=page,
                         per_page=per_page,
                         total_users=total_users)

@app.route('/admin/update_user_role', methods=['POST'])
@login_required
@admin_required
def admin_update_user_role():
    try:
        data = request.get_json()
        user_id = data['user_id']
        new_role = data['role']
        
        # Update user role
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'role': new_role}}
        )
        
        if result.modified_count:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'User not found'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    try:
        # Cannot delete yourself
        if user_id == session['user_id']:
            flash('You cannot delete your own account.', 'error')
            return redirect(url_for('admin_users'))
        
        # Delete user
        result = users_collection.delete_one({'_id': ObjectId(user_id)})
        
        if result.deleted_count:
            # Also delete user's documents
            documents_collection.delete_many({'user_id': user_id})
            flash('User deleted successfully.', 'success')
        else:
            flash('User not found.', 'error')
            
    except Exception as e:
        flash('Error deleting user: ' + str(e), 'error')
    
    return redirect(url_for('admin_users'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)