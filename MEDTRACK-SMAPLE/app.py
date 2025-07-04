from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import boto3
import logging
import os
import uuid
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from boto3.dynamodb.conditions import Key, Attr

# ---------------------------------------
# Load Environment Variables
# ---------------------------------------
if not load_dotenv():
    print("Warning: .env file not found. Using default configurations.")

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'us-east-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# DynamoDB Table Names (Aligned with ER Diagram)
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'WellnessUsers')
DOCTORS_TABLE_NAME = os.environ.get('DOCTORS_TABLE_NAME', 'WellnessDoctors')
PATIENTS_TABLE_NAME = os.environ.get('PATIENTS_TABLE_NAME', 'WellnessPatients')
NOTIFICATIONS_TABLE_NAME = os.environ.get('NOTIFICATIONS_TABLE_NAME', 'WellnessNotifications')
APPOINTMENTS_TABLE_NAME = os.environ.get('APPOINTMENTS_TABLE_NAME', 'WellnessAppointments')
DIAGNOSIS_TABLE_NAME = os.environ.get('DIAGNOSIS_TABLE_NAME', 'WellnessDiagnosis')
# Existing activity/metric tables, now assuming they only store patient data
ACTIVITIES_TABLE_NAME = os.environ.get('ACTIVITIES_TABLE_NAME', 'WellnessUserActivities')
HEALTH_METRICS_TABLE_NAME = os.environ.get('HEALTH_METRICS_TABLE_NAME', 'WellnessHealthMetrics')
GOALS_TABLE_NAME = os.environ.get('GOALS_TABLE_NAME', 'WellnessGoals')

# SNS Configuration
SNS_TOPIC_ARN = arn:aws:sns:us-east-1:253490749648:beautysalon:a7161d75-ba6d-4714-9aaf-a8f4a7ad48c7
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# Login attempt tracking
login_attempts = {}

# ---------------------------------------
# AWS Resources Initialization
# ---------------------------------------
try:
    if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
        dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
        sns = boto3.client('sns', region_name=AWS_REGION_NAME) if ENABLE_SNS else None
        logger.info("AWS DynamoDB and SNS clients initialized.")
    else:
        dynamodb = None
        sns = None
        logger.warning("AWS credentials not found. Running in local mock mode.")

except Exception as e:
    logger.error(f"Error initializing AWS resources: {e}")
    dynamodb = None
    sns = None

# ---------------------------------------
# Mock Database for Local Development (Expanded for all ERD tables)
# ---------------------------------------
local_db = {
    'users': {}, # PK: user_id, stores full user data from Users table
    'users_by_email': {}, # For quick lookup by email for login (simulates GSI)
    'doctors': {}, # PK: doctor_id
    'patients': {}, # PK: patient_id
    'notifications': {}, # PK: notification_id, keyed by user_id for quick lookup
    'appointments': {}, # PK: appointment_id, keyed by patient_id or doctor_id for quick lookup
    'diagnosis': {}, # PK: diagnosis_id, keyed by appointment_id for quick lookup
    'activities': {}, # PK: activity_id, keyed by user_id for quick lookup
    'health_metrics': {}, # PK: metric_id, keyed by user_id for quick lookup
    'goals': {} # PK: goal_id, keyed by user_id for quick lookup
}

# ---------------------------------------
# Database Helper Functions
# ---------------------------------------
def get_table(table_name):
    if dynamodb:
        return dynamodb.Table(table_name)
    return None

def get_user_by_id(user_id):
    if dynamodb:
        try:
            response = get_table(USERS_TABLE_NAME).get_item(Key={'user_id': user_id})
            return response.get('Item')
        except Exception as e:
            logger.error(f"Error fetching user by ID from DynamoDB: {e}")
            return None
    else:
        return local_db['users'].get(user_id)

def get_user_by_email(email):
    if dynamodb:
        try:
            response = get_table(USERS_TABLE_NAME).query(
                IndexName='EmailIndex', # REQUIRES GSI
                KeyConditionExpression=Key('email').eq(email)
            )
            if response['Items']:
                return response['Items'][0]
            return None
        except Exception as e:
            logger.error(f"Error fetching user by email from DynamoDB: {e}")
            return None
    else:
        # Simulate GSI lookup in local_db
        return local_db['users_by_email'].get(email)

def get_doctor_by_userid(user_id):
    if dynamodb:
        try:
            # Assumes you might need a GSI on Doctors table for UserId if direct lookup is common
            # Or you can scan (less efficient) or filter based on a query for DoctorID
            response = get_table(DOCTORS_TABLE_NAME).scan(
                FilterExpression=Attr('UserID').eq(user_id)
            )
            if response['Items']:
                return response['Items'][0]
            return None
        except Exception as e:
            logger.error(f"Error fetching doctor by user ID from DynamoDB: {e}")
            return None
    else:
        for doctor_data in local_db['doctors'].values():
            if doctor_data.get('UserID') == user_id:
                return doctor_data
        return None

def get_patient_by_userid(user_id):
    if dynamodb:
        try:
            # Assumes you might need a GSI on Patients table for UserId if direct lookup is common
            response = get_table(PATIENTS_TABLE_NAME).scan(
                FilterExpression=Attr('UserID').eq(user_id)
            )
            if response['Items']:
                return response['Items'][0]
            return None
        except Exception as e:
            logger.error(f"Error fetching patient by user ID from DynamoDB: {e}")
            return None
    else:
        for patient_data in local_db['patients'].values():
            if patient_data.get('UserID') == user_id:
                return patient_data
        return None


# ---------------------------------------
# Authentication Decorators
# ---------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Authentication required. Please log in.', 'error')
            return redirect(url_for('login_page'))
        # Regenerate session if permanent session lifetime expires but user_id is still present
        session.permanent = True
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Authentication required.', 'error')
                return redirect(url_for('login_page'))
            
            user_role = session.get('role')
            if user_role != required_role:
                flash(f'Access denied. You must be a {required_role}.', 'error')
                # Redirect to dashboard based on their actual role, or home
                if user_role == 'patient':
                    return redirect(url_for('dashboard'))
                elif user_role == 'doctor':
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------------------------------------
# Utility Functions
# ---------------------------------------
def send_email_notification(to_email, subject, body):
    if not ENABLE_EMAIL or not SENDER_EMAIL or not SENDER_PASSWORD:
        logger.info(f"Email notifications are disabled or missing sender credentials. Email not sent: {subject}")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()

        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False

def create_notification(user_id, message):
    notification_id = str(uuid.uuid4())
    notification_data = {
        'notification_id': notification_id,
        'user_id': user_id,
        'message': message,
        'timestamp': datetime.now().isoformat()
    }
    if dynamodb:
        try:
            get_table(NOTIFICATIONS_TABLE_NAME).put_item(Item=notification_data)
            logger.info(f"Notification created for user {user_id}: {message}")
            return True
        except Exception as e:
            logger.error(f"Error creating notification in DynamoDB: {e}")
            return False
    else:
        if user_id not in local_db['notifications']:
            local_db['notifications'][user_id] = []
        local_db['notifications'][user_id].append(notification_data)
        logger.info(f"Notification created in local_db for user {user_id}")
        return True


# ---------------------------------------
# Authentication Routes
# ---------------------------------------
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        role = data.get('role') # Must be 'patient' or 'doctor'
        phone = data.get('phone', '') # Optional
        specialization = data.get('specialty', '') # For doctors
        age = data.get('age') # For patients
        medical_history = data.get('medical_history', '') # For patients

        if not all([email, password, name, role]):
            return jsonify({'error': 'Email, password, name, and role are required'}), 400
        if role not in ['patient', 'doctor']:
            return jsonify({'error': 'Invalid role specified. Must be "patient" or "doctor"'}), 400
        if role == 'patient' and not age:
             return jsonify({'error': 'Age is required for patients'}), 400
        if role == 'doctor' and not specialization:
             return jsonify({'error': 'Specialization is required for doctors'}), 400

        # Check if user already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            return jsonify({'error': 'User with this email already exists'}), 400

        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)

        user_item = {
            'user_id': user_id,
            'name': name,
            'email': email,
            'role': role,
            'password_hash': hashed_password,
            'phone': phone,
            'created_at': datetime.now().isoformat(),
            'is_active': True
        }

        if dynamodb:
            get_table(USERS_TABLE_NAME).put_item(Item=user_item)
        else:
            local_db['users'][user_id] = user_item
            local_db['users_by_email'][email] = user_item

        if role == 'doctor':
            doctor_id = str(uuid.uuid4())
            doctor_item = {
                'doctor_id': doctor_id,
                'UserID': user_id, # Link to Users table
                'Specialization': specialization,
                'Experience': 0 # Assuming new doctors start with 0 experience, can be updated
            }
            if dynamodb:
                get_table(DOCTORS_TABLE_NAME).put_item(Item=doctor_item)
            else:
                local_db['doctors'][doctor_id] = doctor_item
            
            welcome_subject = "Welcome to WellnessTracker as a Doctor!"
            welcome_body = f"Hi Dr. {name},\n\nWelcome to WellnessTracker. Your patients will now be able to connect with you.\n\nBest regards,\nWellnessTracker Team"
        else: # patient role
            patient_id = str(uuid.uuid4())
            patient_item = {
                'patient_id': patient_id,
                'UserID': user_id, # Link to Users table
                'Age': int(age),
                'MedicalHistory': medical_history
            }
            if dynamodb:
                get_table(PATIENTS_TABLE_NAME).put_item(Item=patient_item)
            else:
                local_db['patients'][patient_id] = patient_item
            
            welcome_subject = "Welcome to WellnessTracker!"
            welcome_body = f"Hi {name},\n\nWelcome to WellnessTracker! Start tracking your wellness journey today.\n\nBest regards,\nWellnessTracker Team"
        
        send_email_notification(email, welcome_subject, welcome_body)
        create_notification(user_id, welcome_subject)

        logger.info(f"New {role} registered: {email} (UserID: {user_id})")
        return jsonify({'message': f'{role.capitalize()} registered successfully', 'user_id': user_id}), 201

    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        client_ip = request.remote_addr
        # Basic rate limiting
        if client_ip in login_attempts:
            if login_attempts[client_ip]['count'] >= 5:
                time_diff = datetime.now() - login_attempts[client_ip]['last_attempt']
                if time_diff < timedelta(minutes=15):
                    return jsonify({'error': 'Too many login attempts. Try again later.'}), 429
                else:
                    login_attempts[client_ip] = {'count': 0, 'last_attempt': datetime.now()}

        user_data = get_user_by_email(email)

        if not user_data:
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {'count': 0, 'last_attempt': datetime.now()}
            login_attempts[client_ip]['count'] += 1
            login_attempts[client_ip]['last_attempt'] = datetime.now()
            return jsonify({'error': 'Invalid credentials'}), 401

        if not check_password_hash(user_data['password_hash'], password):
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {'count': 0, 'last_attempt': datetime.now()}
            login_attempts[client_ip]['count'] += 1
            login_attempts[client_ip]['last_attempt'] = datetime.now()
            return jsonify({'error': 'Invalid credentials'}), 401

        if client_ip in login_attempts:
            del login_attempts[client_ip]

        session['user_id'] = user_data['user_id']
        session['email'] = user_data['email']
        session['name'] = user_data['name']
        session['role'] = user_data['role']
        session.permanent = True

        logger.info(f"User logged in: {email} with role: {user_data['role']}")
        return jsonify({
            'message': 'Login successful',
            'user': {
                'user_id': user_data['user_id'],
                'email': user_data['email'],
                'name': user_data['name'],
                'role': user_data['role']
            }
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

# ---------------------------------------
# User Profile Management
# ---------------------------------------
@app.route('/api/profile', methods=['GET'])
@login_required
def get_current_user_profile():
    user_id = session['user_id']
    user_data = get_user_by_id(user_id)

    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    # Fetch role-specific data
    profile = {k: v for k, v in user_data.items() if k not in ['password_hash', 'created_at']}
    
    if user_data['role'] == 'doctor':
        doctor_data = get_doctor_by_userid(user_id)
        if doctor_data:
            profile.update({
                'doctor_id': doctor_data.get('doctor_id'),
                'specialization': doctor_data.get('Specialization'),
                'experience': doctor_data.get('Experience')
            })
    elif user_data['role'] == 'patient':
        patient_data = get_patient_by_userid(user_id)
        if patient_data:
            profile.update({
                'patient_id': patient_data.get('patient_id'),
                'age': patient_data.get('Age'),
                'medical_history': patient_data.get('MedicalHistory')
            })

    return jsonify(profile), 200

@app.route('/api/profile/<user_id>', methods=['GET'])
@login_required
def get_any_user_profile(user_id):
    """Allows doctors to view patient profiles, or admin to view any profile."""
    current_user_id = session['user_id']
    current_user_role = session['role']

    # Doctors can view their patients' profiles
    if current_user_role == 'doctor':
        # Get the doctor's actual patient IDs from the Appointments table (more reliable)
        doctor_appointments_response = None
        if dynamodb:
            try:
                doctor_appointments_response = get_table(APPOINTMENTS_TABLE_NAME).query(
                    IndexName='DoctorID-Date-Index', # GSI on Appointments table
                    KeyConditionExpression=Key('doctor_id').eq(current_user_id)
                )
            except Exception as e:
                logger.error(f"Error fetching doctor's appointments for patient check: {e}")
                return jsonify({'error': 'Failed to verify patient access'}), 500
        else:
            # Local DB simulation
            doctor_appointments_response = {'Items': [app for app in local_db['appointments'].values() if app.get('DoctorID') == current_user_id]}

        if doctor_appointments_response and any(app.get('PatientID') == user_id for app in doctor_appointments_response.get('Items', [])):
            # Proceed to fetch patient's user data
            user_data = get_user_by_id(user_id)
            if not user_data or user_data.get('role') != 'patient':
                return jsonify({'error': 'User not found or not a patient'}), 404

            profile = {k: v for k, v in user_data.items() if k not in ['password_hash', 'created_at']}
            patient_data = get_patient_by_userid(user_id)
            if patient_data:
                profile.update({
                    'patient_id': patient_data.get('patient_id'),
                    'age': patient_data.get('Age'),
                    'medical_history': patient_data.get('MedicalHistory')
                })
            return jsonify(profile), 200
        else:
            return jsonify({'error': 'Access denied: You are not authorized to view this patient\'s profile'}), 403
    
    # Patients can only view their own profile
    elif current_user_role == 'patient':
        if current_user_id != user_id:
            return jsonify({'error': 'Access denied: Patients can only view their own profile'}), 403
        return get_current_user_profile() # Call the existing function for consistency

    else:
        return jsonify({'error': 'Access denied: Unknown role'}), 403

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_user_profile():
    user_id = session['user_id']
    data = request.get_json()
    
    user_table = get_table(USERS_TABLE_NAME)
    doctor_table = get_table(DOCTORS_TABLE_NAME)
    patient_table = get_table(PATIENTS_TABLE_NAME)

    # Update Users table attributes
    update_user_expression_parts = []
    user_expression_attribute_values = {}
    user_expression_attribute_names = {} # For reserved keywords like 'name'

    if 'name' in data:
        update_user_expression_parts.append('#N = :n')
        user_expression_attribute_values[':n'] = data['name']
        user_expression_attribute_names['#N'] = 'name'
        session['name'] = data['name'] # Update session
    if 'phone' in data:
        update_user_expression_parts.append('phone = :p')
        user_expression_attribute_values[':p'] = data['phone']
    
    try:
        if update_user_expression_parts:
            update_expression = 'SET ' + ', '.join(update_user_expression_parts)
            if dynamodb:
                user_table.update_item(
                    Key={'user_id': user_id},
                    UpdateExpression=update_expression,
                    ExpressionAttributeValues=user_expression_attribute_values,
                    ExpressionAttributeNames=user_expression_attribute_names if user_expression_attribute_names else None,
                    ReturnValues='UPDATED_NEW'
                )
            else:
                # Local DB update for Users table
                if user_id in local_db['users']:
                    for key, value in data.items():
                        if key in ['name', 'phone']:
                            local_db['users'][user_id][key] = value

        # Update Doctor/Patient specific attributes
        if session['role'] == 'doctor':
            doctor_data = get_doctor_by_userid(user_id)
            if doctor_data and 'specialization' in data:
                if dynamodb:
                    doctor_table.update_item(
                        Key={'doctor_id': doctor_data['doctor_id']},
                        UpdateExpression='SET Specialization = :s',
                        ExpressionAttributeValues={':s': data['specialization']}
                    )
                else:
                    local_db['doctors'][doctor_data['doctor_id']]['Specialization'] = data['specialization']
            if doctor_data and 'experience' in data: # Also allow updating experience
                 if dynamodb:
                    doctor_table.update_item(
                        Key={'doctor_id': doctor_data['doctor_id']},
                        UpdateExpression='SET Experience = :e',
                        ExpressionAttributeValues={':e': int(data['experience'])}
                    )
                 else:
                    local_db['doctors'][doctor_data['doctor_id']]['Experience'] = int(data['experience'])

        elif session['role'] == 'patient':
            patient_data = get_patient_by_userid(user_id)
            if patient_data and 'age' in data:
                if dynamodb:
                    patient_table.update_item(
                        Key={'patient_id': patient_data['patient_id']},
                        UpdateExpression='SET Age = :a',
                        ExpressionAttributeValues={':a': int(data['age'])}
                    )
                else:
                    local_db['patients'][patient_data['patient_id']]['Age'] = int(data['age'])
            if patient_data and 'medical_history' in data:
                if dynamodb:
                    patient_table.update_item(
                        Key={'patient_id': patient_data['patient_id']},
                        UpdateExpression='SET MedicalHistory = :mh',
                        ExpressionAttributeValues={':mh': data['medical_history']}
                    )
                else:
                    local_db['patients'][patient_data['patient_id']]['MedicalHistory'] = data['medical_history']
        
        logger.info(f"User profile updated for {session['email']}")
        return jsonify({'message': 'Profile updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating user profile: {e}", exc_info=True)
        return jsonify({'error': 'Failed to update profile'}), 500


# ---------------------------------------
# Doctor-Specific Routes
# ---------------------------------------
@app.route('/api/doctors/all', methods=['GET'])
@login_required # Any logged in user can see doctors to choose one
def get_all_doctors():
    """Returns a list of all registered doctors."""
    doctors_list = []
    if dynamodb:
        try:
            response = get_table(DOCTORS_TABLE_NAME).scan() # Scan on doctors table
            for doctor_item in response.get('Items', []):
                user_info = get_user_by_id(doctor_item['UserID'])
                if user_info:
                    doctors_list.append({
                        'doctor_id': doctor_item['doctor_id'],
                        'user_id': doctor_item['UserID'],
                        'name': user_info['name'],
                        'email': user_info['email'],
                        'specialization': doctor_item.get('Specialization', 'N/A'),
                        'experience': doctor_item.get('Experience', 0)
                    })
        except Exception as e:
            logger.error(f"Error scanning doctors in DynamoDB: {e}")
            return jsonify({'error': 'Failed to retrieve doctors'}), 500
    else:
        for doctor_data in local_db['doctors'].values():
            user_info = local_db['users'].get(doctor_data['UserID'])
            if user_info:
                doctors_list.append({
                    'doctor_id': doctor_data['doctor_id'],
                    'user_id': doctor_data['UserID'],
                    'name': user_info['name'],
                    'email': user_info['email'],
                    'specialization': doctor_data.get('Specialization', 'N/A'),
                    'experience': doctor_data.get('Experience', 0)
                })
    return jsonify({'doctors': doctors_list}), 200


@app.route('/api/doctors/my_patients', methods=['GET'])
@login_required
@role_required('doctor')
def get_doctors_patients():
    doctor_user_id = session['user_id']
    
    # Find all appointments for this doctor to identify their patients
    patient_ids = set()
    if dynamodb:
        try:
            response = get_table(APPOINTMENTS_TABLE_NAME).query(
                IndexName='DoctorID-Date-Index', # GSI required
                KeyConditionExpression=Key('doctor_id').eq(doctor_user_id),
                ProjectionExpression='patient_id' # Only fetch patient_id
            )
            for item in response.get('Items', []):
                patient_ids.add(item['patient_id'])
            
            # If you want to check the Patient entity's doctor_id directly
            # This would require a GSI on Patient table: doctor_id -> patient_id
            # response = get_table(PATIENTS_TABLE_NAME).query(
            #     IndexName='DoctorIDIndex', # Requires GSI
            #     KeyConditionExpression=Key('doctor_id').eq(doctor_user_id),
            #     ProjectionExpression='patient_id'
            # )
            # for item in response.get('Items', []):
            #     patient_ids.add(item['patient_id'])

        except Exception as e:
            logger.error(f"Error fetching doctor's patients from DynamoDB: {e}")
            return jsonify({'error': 'Failed to fetch patients'}), 500
    else:
        for appt in local_db['appointments'].values():
            if appt.get('DoctorID') == doctor_user_id:
                patient_ids.add(appt['PatientID'])

    patients_data = []
    for p_id in patient_ids:
        patient_entity = get_table(PATIENTS_TABLE_NAME).get_item(Key={'patient_id': p_id}).get('Item') if dynamodb else local_db['patients'].get(p_id)
        if patient_entity:
            user_info = get_user_by_id(patient_entity['UserID'])
            if user_info:
                patients_data.append({
                    'patient_id': p_id,
                    'user_id': user_info['user_id'],
                    'name': user_info['name'],
                    'email': user_info['email'],
                    'age': patient_entity.get('Age'),
                    'medical_history': patient_entity.get('MedicalHistory')
                })
    
    return jsonify({'patients': patients_data}), 200

# Endpoint for doctor to update patient's medical history (example)
@app.route('/api/doctors/update_patient_medical_history/<patient_user_id>', methods=['PUT'])
@login_required
@role_required('doctor')
def update_patient_medical_history(patient_user_id):
    doctor_user_id = session['user_id']
    data = request.get_json()
    new_medical_history = data.get('medical_history')

    if not new_medical_history:
        return jsonify({'error': 'Medical history is required'}), 400
    
    # First, verify if this patient is indeed under this doctor's care
    # This involves checking if any appointment exists between them
    patient_id_from_user = get_patient_by_userid(patient_user_id)
    if not patient_id_from_user:
        return jsonify({'error': 'Patient user not found'}), 404

    is_patient_of_doctor = False
    if dynamodb:
        try:
            # Query appointments where current doctor is the doctor and patient_user_id is the patient
            response = get_table(APPOINTMENTS_TABLE_NAME).query(
                IndexName='DoctorID-Date-Index', # Use DoctorID GSI
                KeyConditionExpression=Key('doctor_id').eq(doctor_user_id),
                FilterExpression=Attr('patient_id').eq(patient_id_from_user['patient_id']) # Filter by patient_id
            )
            if response.get('Items'):
                is_patient_of_doctor = True
        except Exception as e:
            logger.error(f"Error checking patient ownership for doctor: {e}")
            return jsonify({'error': 'Failed to verify patient ownership'}), 500
    else:
        for appt in local_db['appointments'].values():
            if appt.get('DoctorID') == doctor_user_id and appt.get('PatientID') == patient_id_from_user['patient_id']:
                is_patient_of_doctor = True
                break
    
    if not is_patient_of_doctor:
        return jsonify({'error': 'Access denied: Patient is not assigned to you, or no appointments exist'}), 403

    # Update patient's medical history
    try:
        if dynamodb:
            get_table(PATIENTS_TABLE_NAME).update_item(
                Key={'patient_id': patient_id_from_user['patient_id']},
                UpdateExpression='SET MedicalHistory = :mh',
                ExpressionAttributeValues={':mh': new_medical_history}
            )
        else:
            local_db['patients'][patient_id_from_user['patient_id']]['MedicalHistory'] = new_medical_history
        
        create_notification(patient_user_id, f"Your medical history has been updated by Dr. {session['name']}.")
        logger.info(f"Dr. {session['name']} updated medical history for patient {patient_user_id}")
        return jsonify({'message': 'Patient medical history updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating patient medical history: {e}", exc_info=True)
        return jsonify({'error': 'Failed to update patient medical history'}), 500


# ---------------------------------------
# Notifications
# ---------------------------------------
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    user_id = session['user_id']
    notifications = []
    if dynamodb:
        try:
            response = get_table(NOTIFICATIONS_TABLE_NAME).query(
                IndexName='UserID-Timestamp-Index', # REQUIRES GSI
                KeyConditionExpression=Key('user_id').eq(user_id),
                ScanIndexForward=False, # Newest first
                Limit=10 # Limit to 10 recent notifications
            )
            notifications.extend(response.get('Items', []))
        except Exception as e:
            logger.error(f"Error fetching notifications from DynamoDB: {e}")
    else:
        notifications = local_db['notifications'].get(user_id, [])
        notifications.sort(key=lambda x: x['timestamp'], reverse=True)
        notifications = notifications[:10]

    return jsonify({'notifications': notifications}), 200

# ---------------------------------------
# Appointments (New Entity from ERD)
# ---------------------------------------
@app.route('/api/appointments', methods=['POST'])
@login_required
@role_required('patient') # Only patients can request appointments
def create_appointment():
    try:
        data = request.get_json()
        doctor_user_id = data.get('doctor_user_id') # UserID of the doctor
        appointment_date = data.get('date')
        appointment_time = data.get('time')
        
        if not all([doctor_user_id, appointment_date, appointment_time]):
            return jsonify({'error': 'Doctor, date, and time are required for an appointment'}), 400

        patient_user_id = session['user_id']

        # Get doctor's actual doctor_id
        doctor_entity = get_doctor_by_userid(doctor_user_id)
        if not doctor_entity:
            return jsonify({'error': 'Selected doctor not found'}), 404
        
        # Get patient's actual patient_id
        patient_entity = get_patient_by_userid(patient_user_id)
        if not patient_entity:
            return jsonify({'error': 'Patient entity not found'}), 500 # Should not happen for logged-in user

        appointment_id = str(uuid.uuid4())
        appointment_item = {
            'appointment_id': appointment_id,
            'patient_id': patient_entity['patient_id'], # Store patient_id from Patients table
            'doctor_id': doctor_entity['doctor_id'], # Store doctor_id from Doctors table
            'PatientUserID': patient_user_id, # Store UserID for easier GSI queries
            'DoctorUserID': doctor_user_id, # Store UserID for easier GSI queries
            'Date': appointment_date,
            'Time': appointment_time,
            'Status': 'Scheduled', # Initial status
            'created_at': datetime.now().isoformat()
        }

        if dynamodb:
            get_table(APPOINTMENTS_TABLE_NAME).put_item(Item=appointment_item)
        else:
            local_db['appointments'][appointment_id] = appointment_item
        
        # Notify doctor about new appointment request
        create_notification(doctor_user_id, f"New appointment requested by {session['name']} on {appointment_date} at {appointment_time}.")
        send_email_notification(get_user_by_id(doctor_user_id)['email'], 
                                "New Appointment Request", 
                                f"Dear Dr. {get_user_by_id(doctor_user_id)['name']},\n\n{session['name']} has requested an appointment on {appointment_date} at {appointment_time}.\n\nBest regards,\nWellnessTracker Team")


        logger.info(f"Appointment created: {appointment_id} by {session['name']} with Doctor {doctor_user_id}")
        return jsonify({'message': 'Appointment created successfully', 'appointment_id': appointment_id}), 201

    except Exception as e:
        logger.error(f"Error creating appointment: {e}", exc_info=True)
        return jsonify({'error': 'Failed to create appointment'}), 500

@app.route('/api/appointments', methods=['GET'])
@login_required
def get_appointments():
    user_id = session['user_id']
    role = session['role']
    appointments = []

    if dynamodb:
        try:
            if role == 'patient':
                response = get_table(APPOINTMENTS_TABLE_NAME).query(
                    IndexName='PatientID-Date-Index', # REQUIRES GSI on PatientID and Date
                    KeyConditionExpression=Key('PatientUserID').eq(user_id),
                    ScanIndexForward=False # Newest first
                )
            else: # doctor
                response = get_table(APPOINTMENTS_TABLE_NAME).query(
                    IndexName='DoctorID-Date-Index', # REQUIRES GSI on DoctorID and Date
                    KeyConditionExpression=Key('DoctorUserID').eq(user_id),
                    ScanIndexForward=False
                )
            appointments.extend(response.get('Items', []))
        except Exception as e:
            logger.error(f"Error fetching appointments from DynamoDB for {role}: {e}")
            return jsonify({'error': 'Failed to fetch appointments'}), 500
    else:
        for appt_id, appt in local_db['appointments'].items():
            if (role == 'patient' and appt.get('PatientUserID') == user_id) or \
               (role == 'doctor' and appt.get('DoctorUserID') == user_id):
                appointments.append(appt)
        appointments.sort(key=lambda x: (x['Date'], x['Time']), reverse=True) # Sort by date and time

    # Enrich with names
    for appt in appointments:
        patient_user_info = get_user_by_id(appt['PatientUserID'])
        doctor_user_info = get_user_by_id(appt['DoctorUserID'])
        appt['PatientName'] = patient_user_info['name'] if patient_user_info else 'Unknown Patient'
        appt['DoctorName'] = doctor_user_info['name'] if doctor_user_info else 'Unknown Doctor'
    
    return jsonify({'appointments': appointments}), 200

@app.route('/api/appointments/<appointment_id>/status', methods=['PUT'])
@login_required
@role_required('doctor') # Only doctors can change appointment status
def update_appointment_status(appointment_id):
    try:
        data = request.get_json()
        new_status = data.get('status') # e.g., 'Completed', 'Cancelled'

        if not new_status or new_status not in ['Scheduled', 'Completed', 'Cancelled']:
            return jsonify({'error': 'Invalid status provided'}), 400

        doctor_user_id = session['user_id']
        appointment = get_table(APPOINTMENTS_TABLE_NAME).get_item(Key={'appointment_id': appointment_id}).get('Item') if dynamodb else local_db['appointments'].get(appointment_id)

        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        if appointment['DoctorUserID'] != doctor_user_id:
            return jsonify({'error': 'Access denied: You are not the doctor for this appointment'}), 403

        if dynamodb:
            get_table(APPOINTMENTS_TABLE_NAME).update_item(
                Key={'appointment_id': appointment_id},
                UpdateExpression='SET #S = :s',
                ExpressionAttributeNames={'#S': 'Status'}, # 'Status' is a reserved word
                ExpressionAttributeValues={':s': new_status}
            )
        else:
            local_db['appointments'][appointment_id]['Status'] = new_status
        
        # Notify patient of status change
        create_notification(appointment['PatientUserID'], f"Your appointment on {appointment['Date']} at {appointment['Time']} with Dr. {session['name']} is now {new_status}.")
        send_email_notification(get_user_by_id(appointment['PatientUserID'])['email'],
                                f"Appointment Status Update: {new_status}",
                                f"Dear {get_user_by_id(appointment['PatientUserID'])['name']},\n\nYour appointment on {appointment['Date']} at {appointment['Time']} with Dr. {session['name']} has been updated to '{new_status}'.\n\nBest regards,\nWellnessTracker Team")
        

        logger.info(f"Appointment {appointment_id} status updated to {new_status} by Dr. {session['name']}")
        return jsonify({'message': 'Appointment status updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating appointment status: {e}", exc_info=True)
        return jsonify({'error': 'Failed to update appointment status'}), 500

# ---------------------------------------
# Diagnosis (New Entity from ERD)
# ---------------------------------------
@app.route('/api/appointments/<appointment_id>/diagnosis', methods=['POST'])
@login_required
@role_required('doctor') # Only doctors can create diagnosis
def create_diagnosis(appointment_id):
    try:
        data = request.get_json()
        report = data.get('report')
        diagnosis_date = data.get('date', datetime.now().strftime('%Y-%m-%d')) # Default to today

        if not report:
            return jsonify({'error': 'Diagnosis report is required'}), 400

        doctor_user_id = session['user_id']
        appointment = get_table(APPOINTMENTS_TABLE_NAME).get_item(Key={'appointment_id': appointment_id}).get('Item') if dynamodb else local_db['appointments'].get(appointment_id)

        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        if appointment['DoctorUserID'] != doctor_user_id:
            return jsonify({'error': 'Access denied: You are not the doctor for this appointment'}), 403
        
        # Check if diagnosis already exists for this appointment
        if dynamodb:
            response = get_table(DIAGNOSIS_TABLE_NAME).query(
                IndexName='AppointmentID-Index', # REQUIRES GSI
                KeyConditionExpression=Key('AppointmentID').eq(appointment_id)
            )
            if response.get('Items'):
                return jsonify({'error': 'A diagnosis for this appointment already exists'}), 409
        else:
            # Simulate check in local_db
            for diag_item in local_db['diagnosis'].values():
                if diag_item.get('AppointmentID') == appointment_id:
                    return jsonify({'error': 'A diagnosis for this appointment already exists'}), 409

        diagnosis_id = str(uuid.uuid4())
        diagnosis_item = {
            'diagnosis_id': diagnosis_id,
            'AppointmentID': appointment_id,
            'DoctorID': doctor_user_id, # UserID of doctor
            'PatientID': appointment['PatientUserID'], # UserID of patient
            'Report': report,
            'Date': diagnosis_date,
            'created_at': datetime.now().isoformat()
        }

        if dynamodb:
            get_table(DIAGNOSIS_TABLE_NAME).put_item(Item=diagnosis_item)
        else:
            local_db['diagnosis'][diagnosis_id] = diagnosis_item

        # Notify patient of new diagnosis
        create_notification(appointment['PatientUserID'], f"New diagnosis available from Dr. {session['name']} for your appointment on {appointment['Date']}.")
        send_email_notification(get_user_by_id(appointment['PatientUserID'])['email'],
                                "New Diagnosis Available",
                                f"Dear {get_user_by_id(appointment['PatientUserID'])['name']},\n\nA new diagnosis report from Dr. {session['name']} is available for your appointment on {appointment['Date']}. Please log in to view.\n\nBest regards,\nWellnessTracker Team")

        logger.info(f"Diagnosis created for appointment {appointment_id} by Dr. {session['name']}")
        return jsonify({'message': 'Diagnosis created successfully', 'diagnosis_id': diagnosis_id}), 201

    except Exception as e:
        logger.error(f"Error creating diagnosis: {e}", exc_info=True)
        return jsonify({'error': 'Failed to create diagnosis', 'details': str(e)}), 500

@app.route('/api/diagnosis/<diagnosis_id>', methods=['GET'])
@login_required
def get_single_diagnosis(diagnosis_id):
    user_id = session['user_id']
    role = session['role']

    diagnosis = get_table(DIAGNOSIS_TABLE_NAME).get_item(Key={'diagnosis_id': diagnosis_id}).get('Item') if dynamodb else local_db['diagnosis'].get(diagnosis_id)

    if not diagnosis:
        return jsonify({'error': 'Diagnosis not found'}), 404

    # Access control for diagnosis
    if role == 'patient' and diagnosis['PatientID'] != user_id:
        return jsonify({'error': 'Access denied: You are not authorized to view this diagnosis'}), 403
    elif role == 'doctor' and diagnosis['DoctorID'] != user_id:
        # Doctors can view diagnosis they made OR for their assigned patients
        # For simplicity here, we assume if they are viewing by diagnosis_id, it's theirs or related.
        # A more robust check would involve checking appointments or patient assignment.
        pass # For now, allow doctors to view their own created diagnosis
    else:
        # If user is admin (future role) or specific access granted
        pass

    # Enrich with names
    patient_user_info = get_user_by_id(diagnosis['PatientID'])
    doctor_user_info = get_user_by_id(diagnosis['DoctorID'])
    diagnosis['PatientName'] = patient_user_info['name'] if patient_user_info else 'Unknown Patient'
    diagnosis['DoctorName'] = doctor_user_info['name'] if doctor_user_info else 'Unknown Doctor'


    return jsonify({'diagnosis': diagnosis}), 200

@app.route('/api/diagnosis/patient/<patient_user_id>', methods=['GET'])
@login_required
def get_patient_diagnoses_history(patient_user_id):
    """Allows patients to view their own diagnosis history, and doctors to view their patients' history."""
    current_user_id = session['user_id']
    current_user_role = session['role']
    
    # Check authorization
    authorized = False
    if current_user_role == 'patient' and current_user_id == patient_user_id:
        authorized = True
    elif current_user_role == 'doctor':
        # Check if this doctor is linked to this patient via any appointment
        patient_entity_for_check = get_patient_by_userid(patient_user_id)
        if patient_entity_for_check:
            if dynamodb:
                try:
                    response = get_table(APPOINTMENTS_TABLE_NAME).query(
                        IndexName='DoctorID-Date-Index',
                        KeyConditionExpression=Key('doctor_id').eq(current_user_id),
                        FilterExpression=Attr('patient_id').eq(patient_entity_for_check['patient_id'])
                    )
                    if response.get('Items'):
                        authorized = True
                except Exception as e:
                    logger.error(f"Error checking doctor-patient link for diagnosis history: {e}")
            else:
                for appt in local_db['appointments'].values():
                    if appt.get('DoctorID') == current_user_id and appt.get('PatientID') == patient_entity_for_check['patient_id']:
                        authorized = True
                        break
    
    if not authorized:
        return jsonify({'error': 'Access denied: Not authorized to view this patient\'s diagnosis history'}), 403

    diagnoses = []
    if dynamodb:
        try:
            response = get_table(DIAGNOSIS_TABLE_NAME).query(
                IndexName='PatientID-Date-Index', # REQUIRES GSI
                KeyConditionExpression=Key('PatientID').eq(patient_user_id),
                ScanIndexForward=False # Newest first
            )
            diagnoses.extend(response.get('Items', []))
        except Exception as e:
            logger.error(f"Error fetching diagnoses for patient {patient_user_id} from DynamoDB: {e}")
            return jsonify({'error': 'Failed to fetch diagnoses'}), 500
    else:
        for diag_id, diag in local_db['diagnosis'].items():
            if diag.get('PatientID') == patient_user_id:
                diagnoses.append(diag)
        diagnoses.sort(key=lambda x: x['Date'], reverse=True) # Sort by date

    # Enrich with names
    for diag in diagnoses:
        patient_user_info = get_user_by_id(diag['PatientID'])
        doctor_user_info = get_user_by_id(diag['DoctorID'])
        diag['PatientName'] = patient_user_info['name'] if patient_user_info else 'Unknown Patient'
        diag['DoctorName'] = doctor_user_info['name'] if doctor_user_info else 'Unknown Doctor'

    return jsonify({'diagnoses': diagnoses}), 200


# ---------------------------------------
# Activity Tracking Routes (Specific to patient's own data)
# ---------------------------------------
@app.route('/api/activities', methods=['POST'])
@login_required
@role_required('patient') # Only patients can log their own activities
def log_activity():
    try:
        data = request.get_json()
        activity_type = data.get('activity_type')
        duration = data.get('duration')
        calories_burned = data.get('calories_burned')
        notes = data.get('notes', '')

        if not activity_type or not duration:
            return jsonify({'error': 'Activity type and duration are required'}), 400

        activity_id = str(uuid.uuid4())
        activity_data = {
            'activity_id': activity_id,
            'user_id': session['user_id'], # Patient's UserID
            'activity_type': activity_type,
            'duration': int(duration),
            'calories_burned': int(calories_burned) if calories_burned else 0,
            'notes': notes,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'timestamp': datetime.now().isoformat()
        }

        if dynamodb:
            get_table(ACTIVITIES_TABLE_NAME).put_item(Item=activity_data)
        else:
            if session['user_id'] not in local_db['activities']:
                local_db['activities'][session['user_id']] = []
            local_db['activities'][session['user_id']].append(activity_data)
            local_db['activities'][activity_id] = activity_data # For direct lookup by PK

        logger.info(f"Activity logged: {activity_type} for user {session['user_id']}")
        return jsonify({'message': 'Activity logged successfully', 'activity_id': activity_id}), 201

    except Exception as e:
        logger.error(f"Error logging activity: {e}", exc_info=True)
        return jsonify({'error': 'Failed to log activity'}), 500

@app.route('/api/activities', methods=['GET'])
@login_required
@role_required('patient') # Only patients can view their own activities via this general endpoint
def get_activities():
    try:
        limit = int(request.args.get('limit', 10))
        date_from = request.args.get('date_from')

        activities = []
        if dynamodb:
            response = get_table(ACTIVITIES_TABLE_NAME).query(
                IndexName='UserID-Timestamp-Index', # REQUIRES GSI
                KeyConditionExpression=Key('user_id').eq(session['user_id']),
                ScanIndexForward=False, # Newest first
                Limit=limit
            )
            activities.extend(response.get('Items', []))
        else:
            user_activities_list = local_db['activities'].get(session['user_id'], [])
            activities = sorted(user_activities_list, key=lambda x: x['timestamp'], reverse=True)[:limit]

        if date_from:
            activities = [a for a in activities if a['date'] >= date_from]
            
        return jsonify({'activities': activities}), 200

    except Exception as e:
        logger.error(f"Error fetching activities: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch activities'}), 500

@app.route('/api/patient/<patient_user_id>/activities', methods=['GET'])
@login_required
@role_required('doctor') # Doctors view patient activities
def get_patient_activities_for_doctor(patient_user_id):
    doctor_user_id = session['user_id']
    # Verify doctor is linked to this patient (via appointments for example)
    patient_entity_for_check = get_patient_by_userid(patient_user_id)
    if not patient_entity_for_check:
        return jsonify({'error': 'Patient user not found'}), 404
    
    is_patient_of_doctor = False
    if dynamodb:
        try:
            response = get_table(APPOINTMENTS_TABLE_NAME).query(
                IndexName='DoctorID-Date-Index', # Use DoctorID GSI
                KeyConditionExpression=Key('doctor_id').eq(doctor_user_id),
                FilterExpression=Attr('patient_id').eq(patient_entity_for_check['patient_id']) # Filter by patient_id
            )
            if response.get('Items'):
                is_patient_of_doctor = True
        except Exception as e:
            logger.error(f"Error checking patient ownership for doctor's activity view: {e}")
            return jsonify({'error': 'Failed to verify patient ownership'}), 500
    else:
        for appt in local_db['appointments'].values():
            if appt.get('DoctorID') == doctor_user_id and appt.get('PatientID') == patient_entity_for_check['patient_id']:
                is_patient_of_doctor = True
                break

    if not is_patient_of_doctor:
        return jsonify({'error': 'Access denied: Patient is not assigned to you, or no appointments exist'}), 403

    activities = []
    if dynamodb:
        try:
            response = get_table(ACTIVITIES_TABLE_NAME).query(
                IndexName='UserID-Timestamp-Index', # REQUIRES GSI
                KeyConditionExpression=Key('user_id').eq(patient_user_id),
                ScanIndexForward=False # Newest first
            )
            activities.extend(response.get('Items', []))
        except Exception as e:
            logger.error(f"Error fetching patient activities for doctor from DynamoDB: {e}")
            return jsonify({'error': 'Failed to fetch patient activities'}), 500
    else:
        user_activities_list = local_db['activities'].get(patient_user_id, [])
        activities = sorted(user_activities_list, key=lambda x: x['timestamp'], reverse=True)
            
    return jsonify({'activities': activities}), 200

# ---------------------------------------
# Health Metrics Routes (Specific to patient's own data)
# ---------------------------------------
@app.route('/api/health-metrics', methods=['POST'])
@login_required
@role_required('patient') # Only patients can log their own metrics
def log_health_metric():
    try:
        data = request.get_json()
        metric_type = data.get('metric_type')
        value = data.get('value')
        unit = data.get('unit', '')
        notes = data.get('notes', '')

        if not metric_type or value is None:
            return jsonify({'error': 'Metric type and value are required'}), 400

        metric_id = str(uuid.uuid4())
        metric_data = {
            'metric_id': metric_id,
            'user_id': session['user_id'], # Patient's UserID
            'metric_type': metric_type,
            'value': float(value),
            'unit': unit,
            'notes': notes,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'timestamp': datetime.now().isoformat()
        }

        if dynamodb:
            get_table(HEALTH_METRICS_TABLE_NAME).put_item(Item=metric_data)
        else:
            if session['user_id'] not in local_db['health_metrics']:
                local_db['health_metrics'][session['user_id']] = []
            local_db['health_metrics'][session['user_id']].append(metric_data)
            local_db['health_metrics'][metric_id] = metric_data # For direct lookup by PK

        logger.info(f"Health metric logged: {metric_type} for user {session['user_id']}")
        return jsonify({'message': 'Health metric logged successfully', 'metric_id': metric_id}), 201

    except Exception as e:
        logger.error(f"Error logging health metric: {e}", exc_info=True)
        return jsonify({'error': 'Failed to log health metric'}), 500

@app.route('/api/health-metrics', methods=['GET'])
@login_required
@role_required('patient') # Only patients can view their own metrics via this general endpoint
def get_health_metrics():
    try:
        metric_type = request.args.get('metric_type')
        limit = int(request.args.get('limit', 10))

        metrics = []
        if dynamodb:
            response = get_table(HEALTH_METRICS_TABLE_NAME).query(
                IndexName='UserID-Timestamp-Index', # REQUIRES GSI
                KeyConditionExpression=Key('user_id').eq(session['user_id']),
                ScanIndexForward=False, # Newest first
                Limit=limit
            )
            metrics.extend(response.get('Items', []))
        else:
            user_metrics_list = local_db['health_metrics'].get(session['user_id'], [])
            metrics = sorted(user_metrics_list, key=lambda x: x['timestamp'], reverse=True)[:limit]

        if metric_type:
            metrics = [m for m in metrics if m['metric_type'] == metric_type]
            
        return jsonify({'health_metrics': metrics}), 200

    except Exception as e:
        logger.error(f"Error fetching health metrics: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch health metrics'}), 500

@app.route('/api/patient/<patient_user_id>/metrics', methods=['GET'])
@login_required
@role_required('doctor') # Doctors view patient metrics
def get_patient_metrics_for_doctor(patient_user_id):
    doctor_user_id = session['user_id']
    # Verify doctor is linked to this patient
    patient_entity_for_check = get_patient_by_userid(patient_user_id)
    if not patient_entity_for_check:
        return jsonify({'error': 'Patient user not found'}), 404
    
    is_patient_of_doctor = False
    if dynamodb:
        try:
            response = get_table(APPOINTMENTS_TABLE_NAME).query(
                IndexName='DoctorID-Date-Index', # Use DoctorID GSI
                KeyConditionExpression=Key('doctor_id').eq(doctor_user_id),
                FilterExpression=Attr('patient_id').eq(patient_entity_for_check['patient_id'])
            )
            if response.get('Items'):
                is_patient_of_doctor = True
        except Exception as e:
            logger.error(f"Error checking patient ownership for doctor's metric view: {e}")
            return jsonify({'error': 'Failed to verify patient ownership'}), 500
    else:
        for appt in local_db['appointments'].values():
            if appt.get('DoctorID') == doctor_user_id and appt.get('PatientID') == patient_entity_for_check['patient_id']:
                is_patient_of_doctor = True
                break

    if not is_patient_of_doctor:
        return jsonify({'error': 'Access denied: Patient is not assigned to you, or no appointments exist'}), 403

    metrics = []
    if dynamodb:
        try:
            response = get_table(HEALTH_METRICS_TABLE_NAME).query(
                IndexName='UserID-Timestamp-Index', # REQUIRES GSI
                KeyConditionExpression=Key('user_id').eq(patient_user_id),
                ScanIndexForward=False # Newest first
            )
            metrics.extend(response.get('Items', []))
        except Exception as e:
            logger.error(f"Error fetching patient metrics for doctor from DynamoDB: {e}")
            return jsonify({'error': 'Failed to fetch patient metrics'}), 500
    else:
        user_metrics_list = local_db['health_metrics'].get(patient_user_id, [])
        metrics = sorted(user_metrics_list, key=lambda x: x['timestamp'], reverse=True)
            
    return jsonify({'health_metrics': metrics}), 200

# ---------------------------------------
# Wellness Goals Routes (Specific to patient's own data)
# ---------------------------------------
@app.route('/api/goals', methods=['POST'])
@login_required
@role_required('patient') # Only patients can create their own goals
def create_goal():
    try:
        data = request.get_json()
        goal_type = data.get('goal_type')
        target_value = data.get('target_value')
        current_value = data.get('current_value', 0)
        target_date = data.get('target_date')
        description = data.get('description', '')

        if not goal_type or target_value is None or not target_date:
            return jsonify({'error': 'Goal type, target value, and target date are required'}), 400

        goal_id = str(uuid.uuid4())
        goal_data = {
            'goal_id': goal_id,
            'user_id': session['user_id'], # Patient's UserID
            'goal_type': goal_type,
            'target_value': float(target_value),
            'current_value': float(current_value),
            'target_date': target_date,
            'description': description,
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }

        if dynamodb:
            get_table(GOALS_TABLE_NAME).put_item(Item=goal_data)
        else:
            if session['user_id'] not in local_db['goals']:
                local_db['goals'][session['user_id']] = []
            local_db['goals'][session['user_id']].append(goal_data)
            local_db['goals'][goal_id] = goal_data # For direct lookup by PK

        logger.info(f"Goal created: {goal_type} for user {session['user_id']}")
        return jsonify({'message': 'Goal created successfully', 'goal_id': goal_id}), 201

    except Exception as e:
        logger.error(f"Error creating goal: {e}", exc_info=True)
        return jsonify({'error': 'Failed to create goal'}), 500

@app.route('/api/goals', methods=['GET'])
@login_required
@role_required('patient') # Only patients can view their own goals via this general endpoint
def get_goals():
    try:
        goals = []
        if dynamodb:
            response = get_table(GOALS_TABLE_NAME).query(
                IndexName='UserID-CreatedAt-Index', # REQUIRES GSI
                KeyConditionExpression=Key('user_id').eq(session['user_id']),
                ScanIndexForward=False # Newest first
            )
            user_goals = response.get('Items', [])
        else:
            user_goals = local_db['goals'].get(session['user_id'], [])

        active_goals = [g for g in user_goals if g.get('status') == 'active']
        return jsonify({'goals': active_goals}), 200

    except Exception as e:
        logger.error(f"Error fetching goals: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch goals'}), 500

@app.route('/api/patient/<patient_user_id>/goals', methods=['GET'])
@login_required
@role_required('doctor') # Doctors view patient goals
def get_patient_goals_for_doctor(patient_user_id):
    doctor_user_id = session['user_id']
    # Verify doctor is linked to this patient
    patient_entity_for_check = get_patient_by_userid(patient_user_id)
    if not patient_entity_for_check:
        return jsonify({'error': 'Patient user not found'}), 404
    
    is_patient_of_doctor = False
    if dynamodb:
        try:
            response = get_table(APPOINTMENTS_TABLE_NAME).query(
                IndexName='DoctorID-Date-Index', # Use DoctorID GSI
                KeyConditionExpression=Key('doctor_id').eq(doctor_user_id),
                FilterExpression=Attr('patient_id').eq(patient_entity_for_check['patient_id'])
            )
            if response.get('Items'):
                is_patient_of_doctor = True
        except Exception as e:
            logger.error(f"Error checking patient ownership for doctor's goal view: {e}")
            return jsonify({'error': 'Failed to verify patient ownership'}), 500
    else:
        for appt in local_db['appointments'].values():
            if appt.get('DoctorID') == doctor_user_id and appt.get('PatientID') == patient_entity_for_check['patient_id']:
                is_patient_of_doctor = True
                break

    if not is_patient_of_doctor:
        return jsonify({'error': 'Access denied: Patient is not assigned to you, or no appointments exist'}), 403

    goals = []
    if dynamodb:
        try:
            response = get_table(GOALS_TABLE_NAME).query(
                IndexName='UserID-CreatedAt-Index', # REQUIRES GSI
                KeyConditionExpression=Key('user_id').eq(patient_user_id),
                ScanIndexForward=False # Newest first
            )
            goals.extend(response.get('Items', []))
        except Exception as e:
            logger.error(f"Error fetching patient goals for doctor from DynamoDB: {e}")
            return jsonify({'error': 'Failed to fetch patient goals'}), 500
    else:
        user_goals_list = local_db['goals'].get(patient_user_id, [])
        goals = sorted(user_goals_list, key=lambda x: x['created_at'], reverse=True)
            
    active_goals = [g for g in goals if g.get('status') == 'active']
    return jsonify({'goals': active_goals}), 200

# ---------------------------------------
# Dashboard Route (Updated to be role-aware)
# ---------------------------------------
@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard():
    try:
        user_id = session['user_id']
        user_role = session['role']

        dashboard_data = {
            'user_info': {
                'name': session['name'],
                'email': session['email'],
                'role': user_role
            },
            'stats': {},
            'recent_activities': [],
            'recent_health_metrics': [],
            'active_goals': [],
            'patients_under_care': [], # For doctors
            'upcoming_appointments': [], # For both
            'notifications': [] # For both
        }

        # Fetch notifications for any user
        notifications_response = get_table(NOTIFICATIONS_TABLE_NAME).query(
            IndexName='UserID-Timestamp-Index',
            KeyConditionExpression=Key('user_id').eq(user_id),
            Limit=5,
            ScanIndexForward=False
        ) if dynamodb else {'Items': local_db['notifications'].get(user_id, [])[:5]}
        dashboard_data['notifications'] = notifications_response.get('Items', [])

        # Fetch appointments for any user
        appointments_response = None
        if dynamodb:
            if user_role == 'patient':
                appointments_response = get_table(APPOINTMENTS_TABLE_NAME).query(
                    IndexName='PatientUserID-Date-Index', # Make sure this GSI exists
                    KeyConditionExpression=Key('PatientUserID').eq(user_id),
                    FilterExpression=Attr('Status').eq('Scheduled') | Attr('Status').eq('Rescheduled'),
                    Limit=5,
                    ScanIndexForward=True # Oldest first for upcoming
                )
            elif user_role == 'doctor':
                appointments_response = get_table(APPOINTMENTS_TABLE_NAME).query(
                    IndexName='DoctorUserID-Date-Index', # Make sure this GSI exists
                    KeyConditionExpression=Key('DoctorUserID').eq(user_id),
                    FilterExpression=Attr('Status').eq('Scheduled') | Attr('Status').eq('Rescheduled'),
                    Limit=5,
                    ScanIndexForward=True # Oldest first for upcoming
                )
            
            if appointments_response:
                upcoming_appointments = appointments_response.get('Items', [])
                for appt in upcoming_appointments:
                    patient_user_info = get_user_by_id(appt['PatientUserID'])
                    doctor_user_info = get_user_by_id(appt['DoctorUserID'])
                    appt['PatientName'] = patient_user_info['name'] if patient_user_info else 'Unknown Patient'
                    appt['DoctorName'] = doctor_user_info['name'] if doctor_user_info else 'Unknown Doctor'
                dashboard_data['upcoming_appointments'] = upcoming_appointments

        else: # Local DB
            upcoming_appointments_list = []
            for appt_id, appt in local_db['appointments'].items():
                if (user_role == 'patient' and appt.get('PatientUserID') == user_id and appt.get('Status') in ['Scheduled', 'Rescheduled']) or \
                   (user_role == 'doctor' and appt.get('DoctorUserID') == user_id and appt.get('Status') in ['Scheduled', 'Rescheduled']):
                    upcoming_appointments_list.append(appt)
            upcoming_appointments_list.sort(key=lambda x: (x['Date'], x['Time']))
            upcoming_appointments_list = upcoming_appointments_list[:5]

            for appt in upcoming_appointments_list:
                patient_user_info = local_db['users'].get(appt['PatientUserID'])
                doctor_user_info = local_db['users'].get(appt['DoctorUserID'])
                appt['PatientName'] = patient_user_info['name'] if patient_user_info else 'Unknown Patient'
                appt['DoctorName'] = doctor_user_info['name'] if doctor_user_info else 'Unknown Doctor'
            dashboard_data['upcoming_appointments'] = upcoming_appointments_list


        if user_role == 'patient':
            # Patient dashboard logic
            user_activities_response = get_table(ACTIVITIES_TABLE_NAME).query(IndexName='UserID-Timestamp-Index', KeyConditionExpression=Key('user_id').eq(user_id)) if dynamodb else {'Items': local_db['activities'].get(user_id, [])}
            user_activities = user_activities_response.get('Items', [])

            user_metrics_response = get_table(HEALTH_METRICS_TABLE_NAME).query(IndexName='UserID-Timestamp-Index', KeyConditionExpression=Key('user_id').eq(user_id)) if dynamodb else {'Items': local_db['health_metrics'].get(user_id, [])}
            user_metrics = user_metrics_response.get('Items', [])

            user_goals_response = get_table(GOALS_TABLE_NAME).query(IndexName='UserID-CreatedAt-Index', KeyConditionExpression=Key('user_id').eq(user_id)) if dynamodb else {'Items': local_db['goals'].get(user_id, [])}
            user_goals = user_goals_response.get('Items', [])

            user_activities.sort(key=lambda x: x['timestamp'], reverse=True)
            user_metrics.sort(key=lambda x: x['timestamp'], reverse=True)

            dashboard_data['recent_activities'] = user_activities[:5]
            dashboard_data['recent_health_metrics'] = user_metrics[:5]
            dashboard_data['active_goals'] = [g for g in user_goals if g.get('status') == 'active']

            total_activities = len(user_activities)
            total_calories = sum([a.get('calories_burned', 0) for a in user_activities])

            today = datetime.now()
            week_start = today - timedelta(days=today.weekday())
            this_week_activities = [
                a for a in user_activities
                if datetime.fromisoformat(a['timestamp']).date() >= week_start.date()
            ]

            dashboard_data['stats'] = {
                'total_activities': total_activities,
                'total_calories_burned': total_calories,
                'this_week_activities': len(this_week_activities),
                'active_goals': len(dashboard_data['active_goals'])
            }

        elif user_role == 'doctor':
            # Doctor dashboard logic
            doctor_entity = get_doctor_by_userid(user_id)
            if not doctor_entity:
                return jsonify({'error': 'Doctor entity not found'}), 404

            # Get patients from appointments
            patient_ids_from_appointments = set()
            if dynamodb:
                appts_for_doctor_response = get_table(APPOINTMENTS_TABLE_NAME).query(
                    IndexName='DoctorUserID-Date-Index', # Assuming DoctorUserID GSI
                    KeyConditionExpression=Key('DoctorUserID').eq(user_id),
                    ProjectionExpression='PatientUserID'
                )
                for item in appts_for_doctor_response.get('Items', []):
                    patient_ids_from_appointments.add(item['PatientUserID'])
            else:
                for appt in local_db['appointments'].values():
                    if appt.get('DoctorUserID') == user_id:
                        patient_ids_from_appointments.add(appt['PatientUserID'])
            

            patients_info = []
            if dynamodb:
                for p_user_id in patient_ids_from_appointments:
                    patient_user_info = get_user_by_id(p_user_id)
                    if patient_user_info:
                        patients_info.append({
                            'user_id': patient_user_info['user_id'],
                            'name': patient_user_info['name'],
                            'email': patient_user_info['email']
                        })
            else:
                for p_user_id in patient_ids_from_appointments:
                    patient_user_info = local_db['users'].get(p_user_id)
                    if patient_user_info:
                        patients_info.append({
                            'user_id': patient_user_info['user_id'],
                            'name': patient_user_info['name'],
                            'email': patient_user_info['email']
                        })

            dashboard_data['patients_under_care'] = patients_info
            dashboard_data['stats']['total_patients'] = len(patients_info)
            dashboard_data['stats']['specialization'] = doctor_entity.get('Specialization', 'N/A')
            dashboard_data['stats']['experience'] = doctor_entity.get('Experience', 0)

        return jsonify(dashboard_data), 200

    except Exception as e:
        logger.error(f"Error fetching dashboard data: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch dashboard data'}), 500

# ---------------------------------------
# Template Routes (Updated with role-based redirection)
# ---------------------------------------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Render the appropriate dashboard template based on user role"""
    if session.get('role') == 'doctor':
        return render_template('doctor_dashboard.html')
    elif session.get('role') == 'patient':
        return render_template('patient_dashboard.html')
    else: # Fallback for unknown roles, or if session role somehow missing
        flash('Invalid user role, please contact support.', 'error')
        session.clear()
        return redirect(url_for('login_page'))


@app.route('/patient/activities')
@login_required
@role_required('patient')
def patient_activities_page():
    return render_template('patient_activities.html')

@app.route('/patient/health_metrics')
@login_required
@role_required('patient')
def patient_health_metrics_page():
    return render_template('patient_health_metrics.html')

@app.route('/patient/goals')
@login_required
@role_required('patient')
def patient_goals_page():
    return render_template('patient_goals.html')

@app.route('/patient/appointments')
@login_required
@role_required('patient')
def patient_appointments_page():
    return render_template('patient_appointments.html') # New for patients to manage appointments

@app.route('/patient/diagnoses')
@login_required
@role_required('patient')
def patient_diagnoses_page():
    return render_template('patient_diagnoses.html') # New for patients to view diagnoses

@app.route('/doctor/patients')
@login_required
@role_required('doctor')
def doctor_patients_page():
    return render_template('doctor_patients.html')

@app.route('/doctor/appointments')
@login_required
@role_required('doctor')
def doctor_appointments_page():
    return render_template('doctor_appointments.html') # New for doctors to manage appointments

@app.route('/doctor/patient/<patient_user_id>/details')
@login_required
@role_required('doctor')
def doctor_view_patient_details(patient_user_id):
    # Pass patient_user_id to the template for JS to pick up
    return render_template('doctor_view_patient_details.html', patient_user_id=patient_user_id)

from datetime import date

@app.route('/doctor/appointments/<int:appointment_id>/diagnose')
@login_required
def doctor_diagnose_appointment(appointment_id):
    return render_template(
        'doctor_diagnose_appointment.html',
        appointment_id=appointment_id,
        today=date.today().strftime('%Y-%m-%d')
    )
 # New for doctors to create diagnosis

@app.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html')


# ---------------------------------------
# Health Check Route
# ---------------------------------------
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'WellnessTracker API'
    }), 200

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized access', 'message': str(error)}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden: You do not have permission to access this resource', 'message': str(error)}), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found', 'message': str(error)}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}", exc_info=True)
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500

# ---------------------------------------
# Logging Configuration
# ---------------------------------------
if __name__ == '__main__':
    logger.info("Starting WellnessTracker API server...")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
