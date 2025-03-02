from flask import Flask, request, jsonify, render_template, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_cors import CORS
import os




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'profile_pics'
app.config['SECRET_KEY'] = os.urandom(24)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)



db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)




# --- Models ---
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Pending')  # Example statuses: 'Pending', 'Ongoing', 'Completed'
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<Project {self.title}>"





class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)  # None for private chats
    is_group = db.Column(db.Boolean, default=False)




class UserChat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'))




class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    national_code = db.Column(db.String(10), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    profile_picture = db.Column(db.String(255), nullable=True)
    disabled = db.Column(db.Boolean, default=False, nullable=False)  # Ensure correct definition
    is_admin = db.Column(db.Boolean, default=False)  # Add this line


    # Method to check if the user is disabled
    def is_disabled(self):
        return self.disabled

    # Hash and set the password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)



class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)  # Path to the uploaded file
    upload_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('documents', lazy=True))

    def __repr__(self):
        return f"<Document {self.title} by User {self.user_id}>"

# --- Routes ---

@app.route('/documents', methods=['GET', 'POST'])
@jwt_required()
def manage_documents():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        title = request.form.get('title')
        user_id = get_jwt_identity()
        
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        
        new_document = Document(
            title=title,
            file_path=file_path,
            user_id=user_id
        )
        db.session.add(new_document)
        db.session.commit()
        return jsonify({"message": "Document uploaded successfully!", "document": new_document.id}), 201
    
    documents = Document.query.all()
    return jsonify([{ "id": d.id, "title": d.title, "file_path": d.file_path, "upload_time": d.upload_time, "user_id": d.user_id } for d in documents])




@app.route('/documents/<int:document_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def manage_single_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    if request.method == 'GET':
        return jsonify({"id": document.id, "title": document.title, "file_path": document.file_path, "upload_time": document.upload_time, "user_id": document.user_id})
    
    if request.method == 'PUT':
        data = request.json
        document.title = data.get('title', document.title)
        db.session.commit()
        return jsonify({"message": "Document updated successfully!"})
    
    db.session.delete(document)
    db.session.commit()
    return jsonify({"message": "Document deleted successfully!"})



@app.route('/documents/download/<int:document_id>', methods=['GET'])
@jwt_required()
def download_document(document_id):
    document = Document.query.get_or_404(document_id)
    return send_from_directory('uploads', os.path.basename(document.file_path), as_attachment=True)




@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    username = data.get('username')
    national_code = data.get('national_code')
    email = data.get('email')
    new_password = data.get('new_password')

    # Find the user by username
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    # Validate national code and email
    if user.national_code != national_code or user.email != email:
        return jsonify({"message": "Invalid credentials"}), 401

    # Update the user's password
    user.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({"message": "Password successfully updated"}), 200





@app.route('/admin/projects', methods=['GET', 'POST', 'PUT', 'DELETE'])
def manage_projects():
    # Check if the user is logged in via the session
    if 'user_id' not in session:
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('login'))  # Redirect to login if not authenticated
    
    # Retrieve the current user from the session
    current_user_id = session['user_id']
    admin_user = User.query.get(current_user_id)

    # Ensure the user is an admin
    if not admin_user or not admin_user.is_admin:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('home'))  # Redirect to home or an appropriate page
    
    if request.method == 'GET':
        # Fetch all projects and pass them to the template
        projects = Project.query.all()
        return render_template('projects.html', projects=projects)

    elif request.method == 'POST':
        # Create a new project
        data = request.form
        project_manager = User.query.get(data.get('project_manager_id'))

        if not project_manager or not project_manager.is_project_manager:
            flash("Invalid or unauthorized project manager.", "danger")
            return redirect(url_for('manage_projects'))

        new_project = Project(
            title=data['title'],
            description=data['description'],
            status=data.get('status', 'pending'),  # Default status if not provided
            start_time=datetime.strptime(data['start_time'], '%Y-%m-%d %H:%M:%S'),
            end_time=datetime.strptime(data['end_time'], '%Y-%m-%d %H:%M:%S') if data.get('end_time') else None,
            project_manager=project_manager
        )
        db.session.add(new_project)
        db.session.commit()
        flash("Project created successfully!", "success")
        return redirect(url_for('manage_projects'))

    elif request.method == 'PUT':
        # Update an existing project
        data = request.form
        project = Project.query.get(data['id'])

        if not project:
            flash("Project not found", "danger")
            return redirect(url_for('manage_projects'))

        # Validate and update project manager
        if 'project_manager_id' in data:
            project_manager = User.query.get(data['project_manager_id'])
            if not project_manager or not project_manager.is_project_manager:
                flash("Invalid or unauthorized project manager.", "danger")
                return redirect(url_for('manage_projects'))
            project.project_manager = project_manager

        project.title = data.get('title', project.title)
        project.description = data.get('description', project.description)
        project.status = data.get('status', project.status)
        project.start_time = datetime.strptime(data['start_time'], '%Y-%m-%d %H:%M:%S') if data.get('start_time') else project.start_time
        project.end_time = datetime.strptime(data['end_time'], '%Y-%m-%d %H:%M:%S') if data.get('end_time') else project.end_time

        db.session.commit()
        flash("Project updated successfully!", "success")
        return redirect(url_for('manage_projects'))

    elif request.method == 'DELETE':
        # Delete a project
        data = request.form
        project = Project.query.get(data['id'])

        if not project:
            flash("Project not found", "danger")
            return redirect(url_for('manage_projects'))

        db.session.delete(project)
        db.session.commit()
        flash("Project deleted successfully!", "success")
        return redirect(url_for('manage_projects'))

    return jsonify({"message": "Method not allowed"}), 405



@app.route('/admin/users')
def get_users():
    # Fetch all users from the database
    users_list = User.query.all()
    return render_template('admin_get_users.html', users=users_list)




@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        data = {
            'username': request.form['username'],
            'password': request.form['password'],
            'confirm_password': request.form['confirm_password'],
            'phone_number': request.form['phone_number'],
            'email': request.form['email'],
            'national_code': request.form['national_code']
        }

        # Check if all required fields are filled
        required_fields = ['username', 'password', 'confirm_password', 'phone_number', 'email', 'national_code']
        for field in required_fields:
            if not data.get(field):
                flash(f'{field} is required', 'error')
                return redirect(url_for('admin_register'))

        # Check if the username already exists in the database
        if User.query.filter_by(username=data['username']).first():
            flash("User already exists", 'error')
            return redirect(url_for('admin_register'))

        # Check if passwords match
        if data['password'] != data['confirm_password']:
            flash("Passwords do not match", 'error')
            return redirect(url_for('admin_register'))

        # Create a new user
        user = User(
            username=data['username'],
            phone_number=data['phone_number'],
            email=data['email'],
            national_code=data['national_code'],
            role='admin'
        )

        # Hash and set the password
        user.set_password(data['password'])

        # Add the user to the database
        db.session.add(user)
        db.session.commit()

        flash("Admin registered successfully", 'success')
        return redirect(url_for('admin_register'))

    return render_template('admin_register.html')




@app.route('/register', methods=['POST'])
def register():
    data = request.json
    
    # Ensure required fields are present
    required_fields = ['username', 'password', 'confirm_password', 'phone_number', 'email', 'national_code']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"message": f"{field} is required"}), 400

    # Check if user with the same username exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "User already exists"}), 400
    
    # Check if passwords match
    if data['password'] != data['confirm_password']:
        return jsonify({"message": "Passwords do not match"}), 400
    
    # Create new user
    user = User(
        username=data['username'],  # Make sure username is passed here
        phone_number=data['phone_number'],
        email=data['email'],
        national_code=data['national_code']
    )
    
    # Hash password
    user.set_password(data['password'])
    
    # Add user to database
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"})


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash("Invalid credentials", "error")
            return redirect(url_for('admin_login'))

        if user.disabled:  # Prevent disabled admin users from logging in
            flash("Your account has been disabled", "error")
            return redirect(url_for('admin_login'))

        if user.role != 'admin':
            flash("Access denied. Admins only.", "error")
            return redirect(url_for('admin_login'))
        
        session['user_id'] = user.id
        flash("Logged in successfully", "success")
        return redirect(url_for('get_profile'))  # Redirect to the profile page

    return render_template('admin_login.html')


@app.route('/admin/profile', methods=['GET'])
def get_profile():
    # Check if the user is logged in by verifying the session
    user_id = session.get('user_id')

    if user_id:
        user = User.query.get(user_id)
        if user:
            return render_template('admin_get_profile.html', user=user)
        else:
            flash("User not found. Please log in again.", "error")
            return redirect(url_for('admin_login'))
    
    # If no user is logged in, redirect to login
    flash("You need to log in to access this page.", "error")
    return redirect(url_for('admin_login'))



@app.route('/admin/logout')
def admin_logout():
    session.pop('user_id', None)  # Remove the user_id from the session
    flash("You have been logged out.", "success")
    return redirect(url_for('admin_login'))



@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({"message": "Successfully logged out"})
    unset_jwt_cookies(response)  # Clears the JWT token from cookies
    return response, 200


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({"message": "Invalid credentials"}), 401

    if user.disabled:  # Prevent login for disabled users
        return jsonify({"message": "Your account has been disabled"}), 403

    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))
    return jsonify({"access_token": access_token})


@app.route('/admin/upload_profile_picture', methods=['POST'])
@jwt_required()
def admin_upload_profile_picture():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Ensure user is an admin
    if user.role != 'admin':
        return jsonify({"message": "Access denied. Admins only."}), 403

    # Check if 'profile_picture' is in the request files
    if 'profile_picture' not in request.files:
        return jsonify({"message": "No file uploaded"}), 400
    
    file = request.files['profile_picture']
    
    # Validate file extension
    allowed_extensions = ['jpg', 'jpeg', 'png', 'gif']
    file_extension = file.filename.split('.')[-1].lower()
    
    if file_extension not in allowed_extensions:
        return jsonify({"message": "Invalid file type. Only JPG, JPEG, PNG, and GIF are allowed."}), 400
    
    filename = f'admin_{user_id}.{file_extension}'
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    user.profile_picture = file_path
    db.session.commit()
    
    return jsonify({"message": "Profile picture uploaded successfully", "profile_picture": file_path})


@app.route('/upload_profile_picture', methods=['POST'])
@jwt_required()
def upload_profile_picture():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    # Check if 'profile_picture' is in the request files
    if 'profile_picture' not in request.files:
        return jsonify({"message": "No file uploaded"}), 400
    
    file = request.files['profile_picture']

    # Check if the file has a filename
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    allowed_extensions = ['jpg', 'jpeg', 'png', 'gif']
    file_extension = file.filename.split('.')[-1].lower()

    if file_extension not in allowed_extensions:
        return jsonify({"message": "Invalid file type. Only JPG, JPEG, PNG, and GIF are allowed."}), 400

    filename = f'user_{user_id}.{file_extension}'
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    user.profile_picture = file_path
    db.session.commit()
    
    return jsonify({"message": "Profile picture uploaded successfully", "profile_picture": file_path})


@app.route('/admin/get_profile', methods=['GET'])
@jwt_required()
def admin_get_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Ensure user is an admin
    if user.role != 'admin':
        return jsonify({"message": "Access denied. Admins only."}), 403
    
    return jsonify({
        "username": user.username,
        "email": user.email,
        "profile_picture": user.profile_picture,
        "national_code": user.national_code
    })



@app.route('/get_profile', methods=['GET'])
@jwt_required()
def geet_profile():
    # Get the current user from the JWT token
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    # Return the user details as JSON response
    profile_data = {
        "username": user.username,
        "email": user.email,
        "national_code": user.national_code,
        "profile_picture": user.profile_picture
    }

    return jsonify(profile_data)


@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.phone_number = request.form['phone_number']
        user.national_code = request.form['national_code']
        db.session.commit()
        flash("User updated successfully.", "success")
        return redirect(url_for('get_users'))

    return render_template('edit_user.html', user=user)


@app.route('/admin/edit_profile', methods=['GET', 'POST'])
@jwt_required()
def admin_edit_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    # Ensure the user is an admin
    if user.role != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('home'))  # Redirect to home page if not an admin

    if request.method == 'POST':
        data = request.form  # Get form data

        # Handle username update
        if 'username' in data:
            user.username = data['username']
        
        # Handle phone number update
        if 'phone_number' in data:
            user.phone_number = data['phone_number']
        
        # Handle email update
        if 'email' in data:
            user.email = data['email']
        
        # Handle password update
        if 'current_password' in data and 'new_password' in data:
            if not user.check_password(data['current_password']):
                flash("Current password is incorrect", "danger")
                return redirect(url_for('admin_edit_profile'))

            # Validate new password
            if len(data['new_password']) < 6:
                flash("New password must be at least 6 characters long", "danger")
                return redirect(url_for('admin_edit_profile'))
            
            user.set_password(data['new_password'])

        # Commit the changes to the database
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('admin_edit_profile'))  # Redirect back to edit profile page

    # Render the template with the current user data
    return render_template('edit_profile.html', user=user)


@app.route('/edit_profile', methods=['PUT'])
@jwt_required()
def edit_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.json
    
    # Handle username update
    if 'username' in data:
        user.username = data['username']
    
    # Handle phone number update
    if 'phone_number' in data:
        user.phone_number = data['phone_number']
    
    # Handle email update
    if 'email' in data:
        user.email = data['email']

    # Handle password update
    if 'current_password' in data and 'new_password' in data:
        # Verify the current password
        if not user.check_password(data['current_password']):
            return jsonify({"message": "Current password is incorrect"}), 400
        
        # Validate new password
        if len(data['new_password']) < 6:
            return jsonify({"message": "New password must be at least 6 characters long"}), 400
        
        # Set the new password (hash it before saving)
        user.set_password(data['new_password'])

    # Commit the changes to the database
    db.session.commit()
    
    return jsonify({"message": "Profile updated successfully"})


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(url_for('get_users'))


@app.route('/admin/get_users', methods=['GET'])
@jwt_required()
def get_all_users():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Ensure user is an admin
    if user.role != 'admin':
        return jsonify({"message": "Access denied. Admins only."}), 403
    
    users = User.query.all()
    users_list = [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "phone_number": u.phone_number,
        "national_code": u.national_code,
        "role": u.role,
        "job_title": u.job_title if hasattr(u, 'job_title') else None
    } for u in users]
    
    return jsonify(users_list)


@app.route('/admin/disable_user/<int:user_id>', methods=['POST'])
def disable_user(user_id):
    # Fetch the user by ID
    user = User.query.get_or_404(user_id)

    # Disable the user
    user.disabled = True
    db.session.commit()

    # Flash a message to inform the admin
    flash(f"User {user.username} has been disabled.", "success")
    return redirect(url_for('get_users'))



@app.route('/admin/assign_role', methods=['POST'])
@jwt_required()
def assign_role():
    user_id = get_jwt_identity()
    admin = User.query.get(user_id)
    
    # Ensure user is an admin
    if admin.role != 'admin':
        return jsonify({"message": "Access denied. Admins only."}), 403
    
    data = request.json
    target_user = User.query.get(data.get('user_id'))
    
    if not target_user:
        return jsonify({"message": "User not found."}), 404
    
    allowed_roles = ["backend developer", "frontend developer", "UI designer"]
    if data.get('job_title') not in allowed_roles:
        return jsonify({"message": "Invalid job title."}), 400
    
    target_user.job_title = data.get('job_title')
    db.session.commit()
    
    return jsonify({"message": f"Role {data.get('job_title')} assigned to {target_user.username} successfully."})



@app.route('/create_chat', methods=['POST'])
@jwt_required()
def create_chat():
    data = request.json
    user_id = get_jwt_identity()
    chat = Chat(name=data.get('name'), is_group=data['is_group'])
    db.session.add(chat)
    db.session.commit()
    
    user_chat = UserChat(user_id=user_id, chat_id=chat.id)
    db.session.add(user_chat)
    db.session.commit()
    
    return jsonify({"chat_id": chat.id, "message": "Chat created successfully"})





@app.route('/send_message', methods=['POST'])
@jwt_required()
def send_message():
    data = request.json
    user_id = get_jwt_identity()
    chat = Chat.query.get(data['chat_id'])
    if not chat:
        return jsonify({"message": "Chat not found"}), 404
    
    message = Message(chat_id=chat.id, sender_id=user_id, content=data['content'])
    db.session.add(message)
    db.session.commit()
    
    socketio.emit('new_message', {"chat_id": chat.id, "sender_id": user_id, "content": data['content']}, room=str(chat.id))
    return jsonify({"message": "Message sent"})



# --- WebSockets ---
@socketio.on('join')
def on_join(data):
    chat_id = data['chat_id']
    join_room(str(chat_id))
    emit('status', {"message": "User joined chat"}, room=str(chat_id))

@socketio.on('leave')
def on_leave(data):
    chat_id = data['chat_id']
    leave_room(str(chat_id))
    emit('status', {"message": "User left chat"}, room=str(chat_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
