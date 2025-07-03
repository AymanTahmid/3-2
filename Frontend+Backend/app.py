from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash
from random import randrange
import pickle
from datetime import datetime
import os
import pytz
import random

from database import insert_user, find_user_by_email, update_password_by_email, get_user_profile, get_checkup_history, add_checkup_history,delete_checkup_history

app = Flask(__name__)
app.secret_key = "CardioInsight"

# Email configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "shareserial120@gmail.com"
app.config["MAIL_PASSWORD"] = "wvxh fsvs yfwx zhwk"
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
app.config['MAIL_DEFAULT_SENDER'] = "shareserial120@gmail.com"
app.config['MAIL_DEBUG'] = False
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False
app.config['SESSION_PERMANENT'] = False

mail = Mail(app)

import socket
socket.setdefaulttimeout(5)

# File upload settings
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', msg="Please login to access this page."))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def home():
    msg = request.args.get("msg")  
    msg_type = request.args.get("msg_type")
    
    if session.get('show_login_success'):
        msg = "Logged in successfully!"
        msg_type = "success"
        session.pop('show_login_success', None)
    
    if request.args.get("guest") == "1":
        session.pop('username', None)
        session.pop('user_email', None)
        name = "Guest"
    elif 'username' in session:
        name = session['username']
    else:
        name = "Guest"
    
    return render_template("home.html", name=name, msg=msg, msg_type=msg_type)

@app.route("/find")
@login_required
def find():
    return render_template("find.html", name=session.get("username", "Guest"))

@app.route('/check', methods=['GET', 'POST'])
@login_required
def check():
    msg = None
    if request.method == 'POST':
        # Collect model features
        age = float(request.form["age"])
        sex = int(request.form.get("sex", 1))
        cp = int(request.form["r1"])
        BP = float(request.form["BP"])
        CH = float(request.form["CH"])
        fbs = int(request.form.get("fbs", 0))
        ekg = int(request.form.get("ekg", 0))
        maxhr = float(request.form["maxhr"])
        exercise_angina = int(request.form.get("exercise_angina", 0))
        STD = float(request.form["STD"])
        slope = int(request.form.get("slope", 1))
        fluro = float(request.form["fluro"])
        Th = float(request.form["Th"])  # Thallium
        
        # Prepare input data for model prediction
        d = [[age, sex, cp, BP, CH, fbs, ekg, maxhr, exercise_angina, STD, slope, fluro, Th]]
        
        try:
            # Load both model and scaler
            with open("heartdiseaseprediction.model", "rb") as f:
                model = pickle.load(f)
            with open("scaler.model", "rb") as f:
                scaler = pickle.load(f)
            
            # Scale input data and make prediction
            d_scaled = scaler.transform(d)
            res = model.predict(d_scaled)
            probability = model.predict_proba(d_scaled)[0]
            
            # Format results
            prediction_text = 'Presence' if res[0] == 1 else 'Absence'
            model_confidence = max(probability)
            risk_probability = probability[1]
            
            msg = {
                'prediction': prediction_text,
                'confidence': f"{model_confidence:.2%}",
                'probability_presence': f"{risk_probability:.2%}"
            }
            
        except Exception as e:
            msg = f"Error in prediction: {str(e)}"
            
        # Save to history if user is logged in
        if 'username' in session and isinstance(msg, dict):
            add_checkup_history(session['username'], {
                "age": age, "sex": sex, "cp": cp, "BP": BP, "CH": CH, 
                "fbs": fbs, "ekg": ekg, "maxhr": maxhr, "exercise_angina": exercise_angina,
                "STD": STD, "slope": slope, "fluro": fluro, "Th": Th
            }, msg['prediction'], confidence=msg.get('confidence', 'N/A'), probability_presence=msg.get('probability_presence', 'N/A'))
            
        # Store results and redirect to results page
        session['prediction_results'] = msg
        return redirect(url_for('results'))
        
    return render_template("find.html", msg=None, name=session.get("username", "Guest"))

@app.route('/results')
@app.route('/results/<entry_id>')
@login_required
def results(entry_id=None):
    """Display prediction results on a dedicated page"""
    if entry_id:
        # Load specific historical result
        username = session.get("username")
        if username:
            history = get_checkup_history(username)
            if history:
                # Find entry by timestamp
                for entry in history:
                    if str(entry.get("timestamp")) == entry_id:
                        # Format entry data
                        msg = {
                            "prediction": "Presence" if "Presence" in entry.get("result", "") else "Absence",
                            "confidence": entry.get("confidence", "N/A"),
                            "probability_presence": entry.get("probability_presence", "N/A"),
                            "input_data": entry.get("input", {})
                        }
                        return render_template("results.html", msg=msg, name=username, is_historical=True)
        
        # If entry not found, redirect to profile
        flash("Entry not found.", "error")
        return redirect(url_for('profile'))
    else:
        # Show current session results
        msg = session.get('prediction_results', None)
        # Clear results from session after displaying
        if 'prediction_results' in session:
            del session['prediction_results']
        return render_template("results.html", msg=msg, name=session.get("username", "Guest"), is_historical=False)

@app.route('/input-details/<entry_id>')
@login_required
def input_details(entry_id=None):
    """Display detailed input data for a specific checkup entry"""
    if not entry_id:
        flash("Invalid entry ID.", "error")
        return redirect(url_for('profile'))
    
    username = session.get("username")
    if not username:
        return redirect(url_for('login'))
    
    # Get user's checkup history
    history = get_checkup_history(username)
    if history:
        # Find the specific entry by timestamp
        for entry in history:
            if str(entry.get("timestamp")) == entry_id:
                # Format the entry data for display
                entry_data = {
                    "timestamp": entry.get("timestamp"),
                    "input": entry.get("input", {}),
                    "result": entry.get("result", "N/A"),
                    "date": None,
                    "time": None
                }
                
                # Format the timestamp for display
                if entry_data["timestamp"]:
                    dhaka_tz = pytz.timezone('Asia/Dhaka')
                    
                    # Convert timestamp to Dhaka time
                    if isinstance(entry_data["timestamp"], datetime):
                        if entry_data["timestamp"].tzinfo is None:
                            local_dt = dhaka_tz.localize(entry_data["timestamp"])
                        else:
                            local_dt = entry_data["timestamp"].astimezone(dhaka_tz)
                        entry_data["date"] = local_dt.strftime('%Y-%m-%d')
                        entry_data["time"] = local_dt.strftime('%H:%M:%S')
                    else:
                        entry_data["date"] = "N/A"
                        entry_data["time"] = "N/A"
                
                return render_template("input_details.html", entry=entry_data, name=username)
    
    # If entry not found, redirect to profile
    flash("Entry not found.", "error")
    return redirect(url_for('profile'))

# User signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    msg = None
    msg_type = None
    
    if request.method == "POST":
        username = request.form.get("un", "").strip()
        email = request.form.get("em", "").strip().lower()
        
        # Server-side validation
        if not username or not email:
            msg = "Please fill in all required fields."
            msg_type = "danger"
        elif len(username) < 3:
            msg = "Username must be at least 3 characters long."
            msg_type = "danger"
        elif "@" not in email or "." not in email:
            msg = "Please enter a valid email address."
            msg_type = "danger"
        else:
            try:
                # Check if email already exists
                existing_user = find_user_by_email(email)
                if existing_user:
                    msg = "Email already exists. Please try with a different email address."
                    msg_type = "danger"
                else:
                    # Generate a new 6-digit numeric password
                    new_password = str(random.randint(100000, 999999))
                    
                    # Insert user into database
                    if insert_user(username, new_password, email):
                        # Send welcome email with password
                        email_sent = False
                        try:
                            msg_mail = Message(
                                subject="Welcome to CardioInsight!",
                                sender=app.config["MAIL_USERNAME"],
                                recipients=[email],
                                body=f"""Hello {username},

Welcome to CardioInsight! Your account has been created successfully.

Your login credentials:
Email: {email}
Password: {new_password}

Please login with these credentials. For security, consider changing your password after your first login.

Start your heart health journey today at CardioInsight!

Best regards,
The CardioInsight Team"""
                            )
                            
                            # Send email with timeout handling
                            mail.send(msg_mail)
                            email_sent = True
                            print(f"Welcome email sent successfully to {email}")
                            
                        except Exception as e:
                            print(f"Email sending failed: {e}")
                            # Log password for manual retrieval
                            print(f"MANUAL RETRIEVAL - User: {username}, Email: {email}, Password: {new_password}")
                            
                            # Store in backup file
                            try:
                                with open("temp_passwords.txt", "a") as f:
                                    f.write(f"SIGNUP,{username},{email},{new_password},{datetime.now().isoformat()}\n")
                            except:
                                pass
                        
                        # Success message regardless of email status
                        if email_sent:
                            msg = "Account created successfully! Please check your email for login credentials."
                        else:
                            msg = f"Account created successfully! Email delivery failed. Your password is: {new_password} (Please save this securely)"
                        
                        msg_type = "success"
                        return redirect(url_for("login", msg=msg, msg_type=msg_type))
                    else:
                        msg = "Failed to create account. Please try again."
                        msg_type = "danger"
                        
            except Exception as e:
                print(f"Database error during signup: {e}")
                msg = "An unexpected error occurred. Please try again later."
                msg_type = "danger"
    
    return render_template("signup.html", msg=msg, msg_type=msg_type)

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = request.args.get("msg")
    msg_type = request.args.get("msg_type")
    
    if request.method == "POST":
        email = request.form.get("em", "").strip().lower()
        password = request.form.get("pw", "").strip()
        
        # Basic validation
        if not email or not password:
            msg = "Please enter both email and password."
            msg_type = "danger"
        else:
            try:
                user = find_user_by_email(email)
                if user and check_password_hash(user["password"], password):
                    # Successful login
                    session["username"] = user["username"]
                    session["user_email"] = user["email"]
                    
                    # Show login success toast on home page
                    session['show_login_success'] = True
                    
                    # Redirect to home page
                    return redirect(url_for("home"))
                else:
                    msg = "Invalid email or password. Please try again."
                    msg_type = "danger"
            except Exception as e:
                print(f"Login error: {e}")
                msg = "An error occurred during login. Please try again."
                msg_type = "danger"
    
    return render_template("login.html", msg=msg, msg_type=msg_type)

# Forgot password
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    msg = None
    msg_type = None
    
    if request.method == "POST":
        username = request.form.get("un", "").strip()
        email = request.form.get("em", "").strip().lower()
        
        # Server-side validation
        if not username or not email:
            msg = "Please fill in both username and email fields."
            msg_type = "danger"
        elif len(username) < 3:
            msg = "Username must be at least 3 characters long."
            msg_type = "danger"
        elif "@" not in email or "." not in email:
            msg = "Please enter a valid email address."
            msg_type = "danger"
        else:
            try:
                # Verify user exists with email and username
                user = find_user_by_email(email)
                if user and user["username"].lower().strip() == username.lower().strip():
                    # Generate a new 6-digit numeric password
                    new_password = str(random.randint(100000, 999999))
                    
                    # Update password in database
                    if update_password_by_email(email, new_password):
                        # Send new password via email
                        email_sent = False
                        try:
                            msg_mail = Message(
                                subject="CardioInsight - Password Reset",
                                sender=app.config["MAIL_USERNAME"],
                                recipients=[email],
                                body=f"""Hello {username},

Your password has been successfully reset for your CardioInsight account.

Your new login credentials:
Email: {email}
New Password: {new_password}

Please login with your new password. For security, consider changing it after logging in.

If you did not request this password reset, please contact our support team immediately.

Best regards,
The CardioInsight Team"""
                            )
                            
                            # Send email
                            mail.send(msg_mail)
                            email_sent = True
                            print(f"Password reset email sent successfully to {email}")
                            
                        except Exception as e:
                            print(f"Email sending failed: {e}")
                            # Log password for manual retrieval
                            print(f"MANUAL RETRIEVAL - Password Reset - User: {username}, Email: {email}, New Password: {new_password}")
                            
                            # Store in backup file
                            try:
                                with open("temp_passwords.txt", "a") as f:
                                    f.write(f"RESET,{username},{email},{new_password},{datetime.now().isoformat()}\n")
                            except:
                                pass
                        
                        # Success message regardless of email status
                        if email_sent:
                            msg = "Password reset successfully! Please check your email for the new password."
                        else:
                            msg = f"Password reset successfully! Email delivery failed. Your new password is: {new_password} (Please save this securely)"
                        
                        msg_type = "success"
                        return redirect(url_for("login", msg=msg, msg_type=msg_type))
                    else:
                        msg = "Failed to reset password. Please try again."
                        msg_type = "danger"
                else:
                    msg = "No account found with that username and email combination. Please verify your details."
                    msg_type = "danger"
                    
            except Exception as e:
                print(f"Password reset error: {e}")
                msg = "An unexpected error occurred. Please try again later."
                msg_type = "danger"
    
    return render_template("forgot.html", msg=msg, msg_type=msg_type)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login", logout="1", msg="Logged out successfully!", msg_type="success"))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Check if user is logged in
    if 'username' not in session:
        # Redirect guest users to login page with a message
        return redirect(url_for('login', msg='Please login to access your profile', msg_type='info'))
    
    user = get_user_profile(session['username'])
    history = get_checkup_history(session['username'])
    msg = None

    if request.method == "POST":
        new_username = request.form.get("username")
        new_email = request.form.get("email")
        file = request.files.get("profile_pic")

        # Check for unique email if changed
        if new_email and new_email != user['email']:
            if find_user_by_email(new_email):
                msg = "Email already exists."
                return render_template("profile.html", user=user, history=history, msg=msg)

        # Handle file upload
        profile_pic_url = user.get('profile_pic_url')
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"{session['username']}_profile.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            # Clean up old profile pictures
            for old_ext in ['png', 'jpg', 'jpeg', 'gif']:
                old_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{session['username']}_profile.{old_ext}")
                if os.path.exists(old_file):
                    os.remove(old_file)
            file.save(filepath)
            profile_pic_url = url_for('static', filename=f"uploads/{filename}")

        # Update user in DB
        from database import update_user_profile
        update_user_profile(session['username'], new_username, new_email, profile_pic_url)
        # Update session if username changed
        if new_username and new_username != session['username']:
            session['username'] = new_username

        user = get_user_profile(session['username'])
        msg = "Profile updated successfully."
        msg_type = "success"

    if request.method == "POST" and "delete_id" in request.form:
        timestamp = request.form["delete_id"]
        delete_checkup_history(session["username"], timestamp)
        msg = "Entry deleted successfully!"
        msg_type = "success"
        # Render template with success message
        user = get_user_profile(session["username"])
        history = get_checkup_history(session["username"])
        return render_template("profile.html", user=user, history=history, msg=msg, msg_type=msg_type)

    return render_template("profile.html", user=user, history=history, msg=msg, msg_type=getattr(locals(), 'msg_type', None))

# Template filters
@app.template_filter('todatetime')
def todatetime_filter(s):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return s

@app.template_filter('tolocaltime')
def tolocaltime_filter(dt):
    """Convert datetime to Asia/Dhaka timezone for display"""
    try:
        dhaka_tz = pytz.timezone('Asia/Dhaka')
        
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt)
        
        if isinstance(dt, datetime):
            # If datetime is naive, treat it as already in Asia/Dhaka timezone
            if dt.tzinfo is None:
                return dhaka_tz.localize(dt)
            # If it has timezone info, convert to Dhaka timezone
            return dt.astimezone(dhaka_tz)
        
        return dt
    except Exception:
        # Return current time in Dhaka timezone as fallback
        dhaka_tz = pytz.timezone('Asia/Dhaka')
        return datetime.now(dhaka_tz)

@app.route("/delete-history", methods=["POST"])
@login_required
def delete_history():
    timestamp = request.form.get("delete_id")
    if timestamp:
        from database import delete_checkup_history
        delete_checkup_history(session['username'], timestamp)
    return redirect(url_for('profile'))

# --- Cardiac Info page ---
@app.route("/cardiac-info")
@login_required
def cardiac_info():
    return render_template("cardiac_info.html")

@app.route("/statistics")
@login_required
def statistics():
    return render_template("statistics.html")

@app.route("/prevention")
@login_required
def prevention():
    return render_template("prevention.html")

if __name__ == "__main__":
    app.run(debug=False, port=4000)
