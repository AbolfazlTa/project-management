from flask import Flask, request, jsonify, render_template, flash, redirect, url_for, session, send_from_directory
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
UPLOAD_FOLDER = 'docs'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure 'uploads' directory exists


db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)




# --- Models ---
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Pending')  
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)

    # ✅ Define project manager relationship properly
    project_manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    project_manager = db.relationship('User', back_populates='managed_projects')

    phases = db.relationship('Phase', backref='project', lazy=True, cascade="all, delete-orphan")

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
    role = db.Column(db.String(20), default='user')
    profile_picture = db.Column(db.String(255), nullable=True)
    disabled = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # ✅ Correct relationship definition
    managed_projects = db.relationship('Project', back_populates='project_manager', lazy=True)

    def is_disabled(self):
        return self.disabled

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


class Phase(db.Model):
    __tablename__ = 'phases'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    guess_time = db.Column(db.Integer, nullable=False)  # Guess time in hours/days

    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete="CASCADE"), nullable=False)

    def __repr__(self):
        return f"<Phase {self.title} for Project {self.project_id}>"


class Model(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    uc = db.Column(db.String(255), nullable=False)  # Assuming 'uc' represents something specific
    status = db.Column(db.String(50), nullable=False, default='pending')
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete="CASCADE"), nullable=False)
    
    project = db.relationship('Project', backref=db.backref('models', lazy=True, cascade="all, delete-orphan"))
    
    def __repr__(self):
        return f"<Model {self.title} (UC: {self.uc}, Status: {self.status}) for Project {self.project_id}>"



# Create the database
with app.app_context():
    db.create_all()
    print("Database and tables created successfully!")


# --- Routes ---

@app.route('/projects', methods=['GET', 'POST'])
@jwt_required()
def manage_projects():
    if request.method == 'POST':
        # Creating a new project
        data = request.form

        # Validate required fields
        
        # Create new project
        new_project = Project(
            title=data['title'],
            description=data.get('description', ''),  # Optional
            status=data.get('status', 'Pending'),  # Default is 'Pending'
            start_time=datetime.utcnow()
        )

        db.session.add(new_project)
        db.session.commit()
        session['message'] = "Project created successfully!"
        return redirect(url_for('manage_projects'))

    elif request.method == 'GET':
        # Retrieving all projects
        search_query = session.get('search_query', '')
        if search_query:
            projects = Project.query.filter(Project.title.ilike(f'%{search_query}%')).all()
        else:
            projects = Project.query.all()
        
        return render_template('projects.html', projects=projects, search_query=search_query, message=session.pop('message', None))




@app.route('/projects/search', methods=['POST'])
def search_projects():
    session['search_query'] = request.form.get('search', '')
    return redirect(url_for('manage_projects'))










@app.route('/projects/<int:project_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_project(project_id):
    project = Project.query.get_or_404(project_id)

    if request.method == 'GET':
        # Retrieve a single project
        return jsonify({
            "id": project.id,
            "title": project.title,
            "description": project.description,
            "status": project.status,
            "start_time": project.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": project.end_time.strftime('%Y-%m-%d %H:%M:%S') if project.end_time else None
        })

    elif request.method == 'PUT':
        # Update project details
        data = request.json
        if 'title' in data:
            project.title = data['title']
        if 'description' in data:
            project.description = data['description']
        if 'status' in data:
            project.status = data['status']
        if 'end_time' in data:
            try:
                project.end_time = datetime.strptime(data['end_time'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return jsonify({"error": "Invalid end_time format, use YYYY-MM-DD HH:MM:SS"}), 400

        db.session.commit()
        return jsonify({"message": "Project updated successfully"})

    elif request.method == 'DELETE':
        # Delete a project
        db.session.delete(project)
        db.session.commit()
        return jsonify({"message": "Project deleted successfully"})






@app.route('/admin/phases', methods=['GET'])
@jwt_required()
def admin_search_phases():
    user_id = get_jwt_identity()
    if not is_admin(user_id):
        return jsonify({"error": "Admin access required"}), 403
    
    title_query = request.args.get('title', '')
    phases = Phase.query.filter(Phase.title.ilike(f'%{title_query}%')).all() if title_query else Phase.query.all()
    return jsonify([{ 'id': p.id, 'title': p.title, 'status': p.status, 'start_time': p.start_time.isoformat(), 'end_time': p.end_time.isoformat() if p.end_time else None, 'guess_time': p.guess_time, 'project_id': p.project_id } for p in phases])




@app.route('/admin/phase', methods=['GET', 'POST'])
def admin_manage_phases():
    if request.method == 'POST':
        method_override = request.form.get('_method', '').upper()

        # DELETE Phase
        if method_override == 'DELETE':
            phase_id = request.form.get('id')
            phase = Phase.query.get(phase_id)
            if phase:
                db.session.delete(phase)
                db.session.commit()
                flash("Phase deleted successfully!", "success")
            else:
                flash("Phase not found", "danger")
            return redirect(url_for('admin_manage_phases'))

        # EDIT/UPDATE Phase
        elif method_override == 'PUT':
            phase_id = request.form.get('id')
            phase = Phase.query.get(phase_id)
            if not phase:
                flash("Phase not found", "danger")
                return redirect(url_for('admin_manage_phases'))

            # Update values
            phase.title = request.form.get('title')
            phase.status = request.form.get('status')
            try:
                phase.start_time = datetime.strptime(request.form.get('start_time'), '%Y-%m-%dT%H:%M')
            except ValueError:
                flash("Invalid start time format", "danger")
                return redirect(url_for('admin_manage_phases'))
            phase.guess_time = int(request.form.get('guess_time'))

            db.session.commit()
            flash("Phase updated successfully!", "success")
            return redirect(url_for('admin_manage_phases'))

        else:
            title = request.form.get('title')
            status = request.form.get('status')
            guess_time = request.form.get('guess_time')
            start_time = request.form.get('start_time')
            project_id = request.form.get('project_id')

            if not all([title, status, start_time, guess_time, project_id]):
                flash("All fields are required to create a phase.", "danger")
                return redirect(url_for('admin_manage_phases'))

            try:
                new_phase = Phase(
                    title=title,
                    status=status,
                    guess_time=int(guess_time),
                    start_time=datetime.strptime(start_time, '%Y-%m-%dT%H:%M'),
                    project_id=int(project_id)
                )
                db.session.add(new_phase)
                db.session.commit()
                flash("Phase created successfully!", "success")
            except Exception as e:
                flash(f"Error creating phase: {e}", "danger")

            return redirect(url_for('admin_manage_phases'))
    # GET Request
    phases = Phase.query.all()
    projects = Project.query.all()
    return render_template('admin_phase.html', phases=phases, projects=projects)






@app.route('/admin/phase/<int:phase_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_phase(phase_id):
    user_id = get_jwt_identity()  # Get the ID of the authenticated user
    user = User.query.get(user_id)  # Fetch user details

    if not user or user.role != 'admin':  # Check if user is admin
        return jsonify({"error": "Unauthorized access"}), 403

    phase = Phase.query.get_or_404(phase_id)

    if request.method == 'GET':
        return jsonify({
            "id": phase.id,
            "title": phase.title,
            "status": phase.status,
            "start_time": phase.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": phase.end_time.strftime('%Y-%m-%d %H:%M:%S') if phase.end_time else None,
            "guess_time": phase.guess_time,
            "project_id": phase.project_id
        })

    elif request.method == 'PUT':
        data = request.json
        if 'title' in data:
            phase.title = data['title']
        if 'status' in data:
            phase.status = data['status']
        if 'start_time' in data:
            try:
                phase.start_time = datetime.strptime(data['start_time'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return jsonify({"error": "Invalid start_time format, use YYYY-MM-DD HH:MM:SS"}), 400
        if 'end_time' in data:
            try:
                phase.end_time = datetime.strptime(data['end_time'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return jsonify({"error": "Invalid end_time format, use YYYY-MM-DD HH:MM:SS"}), 400
        if 'guess_time' in data:
            phase.guess_time = data['guess_time']

        db.session.commit()
        return jsonify({"message": "Phase updated successfully"})

    elif request.method == 'DELETE':
        db.session.delete(phase)
        db.session.commit()
        return jsonify({"message": "Phase deleted successfully"})






@app.route('/admin/documents', methods=['GET', 'POST'])
@jwt_required()
def manage_documents():
    claims = get_jwt()  # Get JWT claims
    if claims.get("role") != "admin":
        return jsonify({"error": "Unauthorized access"}), 403  # Restrict non-admin users

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        title = request.form.get('title')
        user_id = get_jwt_identity()
        
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        
        file_path = os.path.join('docs', file.filename)
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
    return jsonify([
        { "id": d.id, "title": d.title, "file_path": d.file_path, "upload_time": d.upload_time, "user_id": d.user_id } 
        for d in documents
    ])






@app.route('/admin/documents/<int:document_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def manage_single_document(document_id):
    claims = get_jwt()  # Get JWT claims
    if claims.get("role") != "admin":
        return jsonify({"error": "Unauthorized access"}), 403  # Restrict non-admin users

    document = Document.query.get_or_404(document_id)
    
    if request.method == 'GET':
        return jsonify({
            "id": document.id,
            "title": document.title,
            "file_path": document.file_path,
            "upload_time": document.upload_time,
            "user_id": document.user_id
        })
    
    if request.method == 'PUT':
        data = request.json
        document.title = data.get('title', document.title)
        db.session.commit()
        return jsonify({"message": "Document updated successfully!"})
    
    db.session.delete(document)
    db.session.commit()
    return jsonify({"message": "Document deleted successfully!"})



@app.route('/admin/documents/download/<int:document_id>', methods=['GET'])
@jwt_required()
def download_document(document_id):
    claims = get_jwt()  # Get JWT claims
    if claims.get("role") != "admin":
        return jsonify({"error": "Unauthorized access"}), 403  # Restrict non-admin users

    document = Document.query.get_or_404(document_id)
    return send_from_directory('docs', os.path.basename(document.file_path), as_attachment=True)




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





@app.route('/admin/project', methods=['GET', 'POST', 'PUT', 'DELETE'])
def manage_project():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('login'))  # Adjust for your login route

    current_user_id = session['user_id']
    admin_user = User.query.get(current_user_id)

    if not admin_user:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('get_profile'))  # Adjust for your profile route

    # Get form data
    data = request.form

    # Handle method override (_method hidden field)
    if data.get("_method") == "DELETE":
        request.method = "DELETE"
    elif data.get("_method") == "PUT":
        request.method = "PUT"

    # **GET REQUEST - Load projects and users**
    if request.method == 'GET':
        users = User.query.all()  # Get all users for project manager selection
        projects = Project.query.all()  # Get all projects
        return render_template('projects.html', projects=projects, users=users)

    # **POST REQUEST - Create a new project**
    elif request.method == 'POST':
        title = data.get('title')
        description = data.get('description')
        status = data.get('status', 'Pending')
        start_time = data.get('start_time')
        end_time = data.get('end_time', None)
        project_manager_id = data.get('project_manager_id')

        # Ensure all required fields are filled
        if not title or not start_time or not project_manager_id:
            flash("Title, Start Time, and Project Manager are required.", "danger")
            return redirect(url_for('manage_project'))

        project_manager = User.query.get(project_manager_id)
        if not project_manager:
            flash("Project manager not found.", "danger")
            return redirect(url_for('manage_project'))

        # Create the project
        new_project = Project(
            title=title,
            description=description,
            status=status,
            start_time=datetime.strptime(start_time, '%Y-%m-%dT%H:%M'),
            end_time=datetime.strptime(end_time, '%Y-%m-%dT%H:%M') if end_time else None,
            project_manager_id=project_manager.id
        )

        db.session.add(new_project)
        db.session.commit()
        flash("Project created successfully!", "success")
        return redirect(url_for('manage_project'))

    # **PUT REQUEST - Edit an existing project**
    elif request.method == 'PUT':
        project_id = data.get('id')
        project = Project.query.get(project_id)

        if not project:
            flash("Project not found", "danger")
            return redirect(url_for('manage_project'))

        # Update project details
        project.title = data.get('title', project.title)
        project.description = data.get('description', project.description)
        project.status = data.get('status', project.status)
        project.start_time = datetime.strptime(data['start_time'], '%Y-%m-%dT%H:%M') if data.get('start_time') else project.start_time
        project.end_time = datetime.strptime(data['end_time'], '%Y-%m-%dT%H:%M') if data.get('end_time') else project.end_time

        # Update project manager if provided
        project_manager_id = data.get('project_manager_id')
        if project_manager_id:
            project_manager = User.query.get(project_manager_id)
            if not project_manager:
                flash("Invalid project manager.", "danger")
                return redirect(url_for('manage_project'))
            project.project_manager_id = project_manager.id

        db.session.commit()
        flash("Project updated successfully!", "success")
        return redirect(url_for('manage_project'))

    # **DELETE REQUEST - Remove a project**
    elif request.method == 'DELETE':
        project_id = data.get('id')
        project = Project.query.get(project_id)

        if not project:
            flash("Project not found", "danger")
            return redirect(url_for('manage_project'))

        db.session.delete(project)
        db.session.commit()
        flash("Project deleted successfully!", "success")
        return redirect(url_for('manage_project'))

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
        # Update profile fields
        user.username = request.form['username']
        user.email = request.form['email']
        user.phone_number = request.form['phone_number']
        user.national_code = request.form['national_code']

        # Verify current password
        current_password = request.form['current_password']
        if not check_password_hash(user.password, current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(request.url)

        # Optional new password
        new_password = request.form['new_password']
        if new_password:
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash("User updated successfully.", "success")
        return redirect(url_for('get_users'))  # or redirect to profile

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


@app.route('/admin/enable_user/<int:user_id>', methods=['POST'])
def enable_user(user_id):
    user = User.query.get(user_id)
    
    if user:
        user.disabled = False
        db.session.commit()
        flash("User has been enabled.", "success")
    else:
        flash("User not found.", "error")
    
    return redirect(url_for('get_users'))  # Redirect to your user management page






@app.route('/admin/disable_user/<int:user_id>', methods=['POST'])
def disable_user(user_id):
    user = User.query.get(user_id)
    
    if user:
        user.disabled = True  # Set the user as disabled
        db.session.commit()
        flash(f"User {user.username} has been disabled.", "success")
    else:
        flash("User not found", "error")

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
    app.run(debug=True)
