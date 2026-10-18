
import os
import re
import time
import secrets
import smtplib
from email.message import EmailMessage

import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# ============================================================
# ENVIRONMENT CONFIG
# ============================================================

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Add a strong SECRET_KEY to your .env file."
    )


# ============================================================
# DATABASE CONFIG
# ============================================================

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "root"),
    "database": os.getenv("DB_NAME", "InterviewBridge"),
}


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ============================================================
# UPLOAD CONFIG
# ============================================================

UPLOAD_FOLDER = os.path.join(
    app.root_path,
    "static",
    "uploads",
    "college_ids",
)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
MAX_FILE_SIZE = 3 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Allow multipart form overhead while validating the photo separately.
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + 512 * 1024


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ============================================================
# VALIDATION HELPERS
# ============================================================

def valid_email(email):
    return bool(
        re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            email,
        )
    )


def valid_phone(phone):
    # International format, for example +919876543210
    return bool(re.fullmatch(r"\+[1-9]\d{7,14}", phone))


def json_error(message, status=400):
    return jsonify(success=False, message=message), status


# ============================================================
# OTP CONFIG
# ============================================================

OTP_EXPIRY_SECONDS = 300
otp_store = {}


def generate_otp():
    return str(secrets.randbelow(900000) + 100000)


def save_otp(kind, destination, otp):
    otp_store[(kind, destination)] = {
        "otp": otp,
        "created_at": time.time(),
        "attempts": 0,
    }


def verify_otp(kind, destination, submitted_otp):
    key = (kind, destination)
    record = otp_store.get(key)

    if not record:
        return False, "Please request a new OTP."

    if time.time() - record["created_at"] > OTP_EXPIRY_SECONDS:
        otp_store.pop(key, None)
        return False, "OTP expired. Please request a new one."

    if record["attempts"] >= 5:
        otp_store.pop(key, None)
        return False, "Too many incorrect attempts. Request a new OTP."

    if not secrets.compare_digest(
        record["otp"],
        submitted_otp.strip(),
    ):
        record["attempts"] += 1
        return False, "Incorrect OTP."

    otp_store.pop(key, None)
    return True, "OTP verified successfully."


def clear_signup_verification():
    keys = (
        "email_verified",
        "mobile_verified",
        "email_otp_destination",
        "mobile_otp_destination",
    )

    for key in keys:
        session.pop(key, None)


def clear_mentor_verification():
    keys = (
        "mentor_email_verified",
        "mentor_mobile_verified",
        "mentor_email_otp_destination",
        "mentor_mobile_otp_destination",
    )

    for key in keys:
        session.pop(key, None)


# ============================================================
# EMAIL OTP HELPER
# ============================================================

def send_email_otp(email, otp):
    mail_username = os.getenv("MAIL_USERNAME")
    mail_password = os.getenv("MAIL_PASSWORD")
    mail_server = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    mail_port = int(os.getenv("MAIL_PORT", "587"))

    if not mail_username or not mail_password:
        raise ValueError(
            "MAIL_USERNAME or MAIL_PASSWORD is missing in .env"
        )

    message = EmailMessage()
    message["Subject"] = "InterviewBridge Email Verification"
    message["From"] = mail_username
    message["To"] = email

    message.set_content(
        f"Your InterviewBridge verification OTP is {otp}.\n"
        "It expires in 5 minutes.\n"
        "Do not share this code with anyone."
    )

    with smtplib.SMTP(mail_server, mail_port, timeout=20) as smtp:
        smtp.starttls()
        smtp.login(mail_username, mail_password)
        smtp.send_message(message)


# ============================================================
# TWILIO VERIFY HELPERS
# ============================================================

def get_twilio_client():
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")

    if not account_sid or not auth_token:
        raise ValueError("Twilio credentials are missing in .env")

    return Client(account_sid, auth_token)


def get_verify_service_sid():
    service_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID")

    if not service_sid:
        raise ValueError(
            "TWILIO_VERIFY_SERVICE_SID is missing in .env"
        )

    return service_sid


def send_sms_otp(phone):
    client = get_twilio_client()
    service_sid = get_verify_service_sid()

    verification = client.verify.v2.services(
        service_sid
    ).verifications.create(
        to=phone,
        channel="sms",
    )

    return verification.status


def check_sms_otp(phone, otp):
    client = get_twilio_client()
    service_sid = get_verify_service_sid()

    result = client.verify.v2.services(
        service_sid
    ).verification_checks.create(
        to=phone,
        code=otp,
    )

    return result.status == "approved"


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# ACCOUNT TYPE
# ============================================================

@app.route("/account-type")
def account_type():
    return render_template("account_type.html")


# ============================================================
# MENTOR LOGIN
# ============================================================

@app.route("/mentor-login", methods=["GET", "POST"])
def mentor_login():
    if request.method == "GET":
        return render_template("mentor_login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        flash("Enter your email and password.", "error")
        return redirect(url_for("mentor_login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT mentor_id, name, email, password
            FROM mentors
            WHERE email = %s
            LIMIT 1
            """,
            (email,),
        )

        mentor = cursor.fetchone()

        if mentor and check_password_hash(
            mentor["password"], password
        ):
            session.clear()
            session["mentor_id"] = mentor["mentor_id"]
            session["mentor_name"] = mentor["name"]

            flash(
                f"Welcome to InterviewBridge, {mentor['name']}!",
                "success",
            )
            return redirect(url_for("home"))

        flash("Invalid mentor email or password.", "error")
        return redirect(url_for("mentor_login"))

    except Error:
        app.logger.exception("Mentor login failed")
        flash("Unable to log in. Check the mentors table.", "error")
        return redirect(url_for("mentor_login"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# MENTOR: SEND EMAIL OTP
# POST /mentor/send-email-otp
# ============================================================

@app.route("/mentor/send-email-otp", methods=["POST"])
def mentor_send_email_otp():
    email = request.form.get("email", "").strip().lower()

    if not valid_email(email):
        return json_error("Enter a valid email address.")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT mentor_id FROM mentors WHERE email = %s LIMIT 1",
            (email,),
        )

        if cursor.fetchone():
            return json_error(
                "This email is already registered.",
                409,
            )

        otp = generate_otp()
        send_email_otp(email, otp)
        save_otp("mentor_email", email, otp)

        session["mentor_email_verified"] = False
        session["mentor_email_otp_destination"] = email

        return jsonify(
            success=True,
            message="Mentor email OTP sent successfully.",
        )

    except Exception:
        app.logger.exception("Mentor email OTP sending failed")
        return json_error(
            "Could not send email OTP. Check your email settings.",
            500,
        )

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# MENTOR: VERIFY EMAIL OTP
# POST /mentor/verify-email-otp
# ============================================================

@app.route("/mentor/verify-email-otp", methods=["POST"])
def mentor_verify_email_otp():
    email = request.form.get("email", "").strip().lower()
    otp = request.form.get("otp", "").strip()

    if not email or not otp:
        return json_error("Enter your email and OTP.")

    if session.get("mentor_email_otp_destination") != email:
        return json_error(
            "Request a new OTP for this email address."
        )

    success, message = verify_otp("mentor_email", email, otp)

    if success:
        session["mentor_email_verified"] = True
        return jsonify(success=True, message=message)

    session["mentor_email_verified"] = False
    return json_error(message)


# ============================================================
# MENTOR: SEND MOBILE OTP
# POST /mentor/send-mobile-otp
# ============================================================

@app.route("/mentor/send-mobile-otp", methods=["POST"])
def mentor_send_mobile_otp():
    phone = request.form.get("phone", "").strip()

    if not valid_phone(phone):
        return json_error(
            "Enter your phone number with country code, e.g. +919876543210."
        )

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT mentor_id FROM mentors WHERE phone = %s LIMIT 1",
            (phone,),
        )

        if cursor.fetchone():
            return json_error(
                "This phone number is already registered.",
                409,
            )

        status = send_sms_otp(phone)

        session["mentor_mobile_verified"] = False
        session["mentor_mobile_otp_destination"] = phone

        app.logger.info("Mentor Twilio Verify status: %s", status)

        return jsonify(
            success=True,
            message="Mentor mobile OTP sent successfully.",
        )

    except TwilioRestException as error:
        app.logger.error(
            "Mentor Twilio send error: code=%s status=%s",
            error.code,
            error.status,
        )
        return json_error(
            "Twilio could not send the OTP. Check your Twilio settings.",
            400,
        )

    except Exception:
        app.logger.exception("Mentor mobile OTP sending failed")
        return json_error(
            "Could not send mobile OTP. Check your configuration.",
            500,
        )

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# MENTOR: VERIFY MOBILE OTP
# POST /mentor/verify-mobile-otp
# ============================================================

@app.route("/mentor/verify-mobile-otp", methods=["POST"])
def mentor_verify_mobile_otp():
    phone = request.form.get("phone", "").strip()
    otp = request.form.get("otp", "").strip()

    if not phone or not otp:
        return json_error("Enter your phone number and OTP.")

    if not valid_phone(phone):
        return json_error("Enter a valid phone number.")

    if session.get("mentor_mobile_otp_destination") != phone:
        return json_error(
            "Request a new OTP for this phone number."
        )

    try:
        approved = check_sms_otp(phone, otp)

        if approved:
            session["mentor_mobile_verified"] = True
            return jsonify(
                success=True,
                message="Mentor mobile OTP verified successfully.",
            )

        session["mentor_mobile_verified"] = False
        return json_error("Incorrect or expired mobile OTP.")

    except TwilioRestException:
        app.logger.exception("Mentor Twilio verification failed")
        session["mentor_mobile_verified"] = False
        return json_error(
            "Twilio could not verify the OTP.",
            400,
        )

    except Exception:
        app.logger.exception("Mentor mobile verification failed")
        return json_error(
            "Could not verify OTP. Please try again.",
            500,
        )


# ============================================================
# MENTOR SIGNUP
# Requires both email and mobile OTP verification.
# ============================================================

@app.route("/mentor-signup", methods=["GET", "POST"])
def mentor_signup():
    if request.method == "GET":
        return render_template("mentor_signup.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()

    company_name = request.form.get("company_name", "").strip()
    role = request.form.get("role", "").strip()
    registration_no = request.form.get("registration_no", "").strip()
    about = request.form.get("about", "").strip()
    city = request.form.get("city", "").strip()

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not all([name, email, phone, password, confirm_password]):
        flash("Please complete all required fields.", "error")
        return redirect(url_for("mentor_signup"))

    if not valid_email(email):
        flash("Enter a valid email address.", "error")
        return redirect(url_for("mentor_signup"))

    if not valid_phone(phone):
        flash(
            "Enter your phone number with country code, e.g. +919876543210.",
            "error",
        )
        return redirect(url_for("mentor_signup"))

    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "error")
        return redirect(url_for("mentor_signup"))

    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for("mentor_signup"))

    # Require both OTPs to be verified for the submitted destinations.
    if session.get("mentor_email_verified") is not True:
        flash("Please verify your email OTP first.", "error")
        return redirect(url_for("mentor_signup"))

    if session.get("mentor_mobile_verified") is not True:
        flash("Please verify your mobile OTP first.", "error")
        return redirect(url_for("mentor_signup"))

    if session.get("mentor_email_otp_destination") != email:
        flash("Your verified email does not match.", "error")
        return redirect(url_for("mentor_signup"))

    if session.get("mentor_mobile_otp_destination") != phone:
        flash("Your verified phone number does not match.", "error")
        return redirect(url_for("mentor_signup"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT mentor_id
            FROM mentors
            WHERE email = %s OR phone = %s
            LIMIT 1
            """,
            (email, phone),
        )

        if cursor.fetchone():
            flash(
                "This email or phone number is already registered.",
                "error",
            )
            return redirect(url_for("mentor_signup"))

        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO mentors (
                name,
                email,
                phone,
                company_name,
                role,
                registration_no,
                about,
                city,
                password
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                name,
                email,
                phone,
                company_name,
                role,
                registration_no,
                about,
                city,
                hashed_password,
            ),
        )

        connection.commit()

        clear_mentor_verification()

        flash(
            "Mentor registration successful. Please log in.",
            "success",
        )
        return redirect(url_for("mentor_login"))

    except Error:
        if connection and connection.is_connected():
            connection.rollback()

        app.logger.exception("Mentor signup failed")
        flash(
            "Mentor signup failed. Check the mentors table and try again.",
            "error",
        )
        return redirect(url_for("mentor_signup"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# STUDENT SIGNUP PAGE
# ============================================================

@app.route("/signup", methods=["GET"])
def signup():
    return render_template("signup.html")


# ============================================================
# STUDENT: SEND EMAIL OTP
# ============================================================

@app.route("/send-email-otp", methods=["POST"])
def send_email_otp_route():
    email = request.form.get("email", "").strip().lower()

    if not valid_email(email):
        return json_error("Enter a valid email address.")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT student_id FROM students WHERE email = %s LIMIT 1",
            (email,),
        )

        if cursor.fetchone():
            return json_error(
                "This email is already registered.",
                409,
            )

        otp = generate_otp()
        send_email_otp(email, otp)
        save_otp("email", email, otp)

        session["email_verified"] = False
        session["email_otp_destination"] = email

        return jsonify(
            success=True,
            message="Email OTP sent successfully.",
        )

    except Exception:
        app.logger.exception("Student email OTP sending failed")
        return json_error(
            "Could not send email OTP. Check your email settings.",
            500,
        )

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# STUDENT: VERIFY EMAIL OTP
# ============================================================

@app.route("/verify-email-otp", methods=["POST"])
def verify_email_otp_route():
    email = request.form.get("email", "").strip().lower()
    otp = request.form.get("otp", "").strip()

    if not email or not otp:
        return json_error("Enter your email and OTP.")

    if session.get("email_otp_destination") != email:
        return json_error(
            "Request a new OTP for this email address."
        )

    success, message = verify_otp("email", email, otp)

    if success:
        session["email_verified"] = True
        return jsonify(success=True, message=message)

    session["email_verified"] = False
    return json_error(message)


# ============================================================
# STUDENT: SEND MOBILE OTP
# ============================================================

@app.route("/send-mobile-otp", methods=["POST"])
def send_mobile_otp_route():
    phone = request.form.get("phone", "").strip()

    if not valid_phone(phone):
        return json_error(
            "Enter a valid phone number with country code."
        )

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT student_id FROM students WHERE phone = %s LIMIT 1",
            (phone,),
        )

        if cursor.fetchone():
            return json_error(
                "This phone number is already registered.",
                409,
            )

        status = send_sms_otp(phone)

        session["mobile_verified"] = False
        session["mobile_otp_destination"] = phone

        app.logger.info("Student Twilio Verify status: %s", status)

        return jsonify(
            success=True,
            message="Mobile OTP sent successfully.",
        )

    except TwilioRestException:
        app.logger.exception("Student Twilio send failed")
        return json_error(
            "Twilio could not send the OTP. Check your Twilio settings.",
            400,
        )

    except Exception:
        app.logger.exception("Student mobile OTP sending failed")
        return json_error(
            "Could not send mobile OTP. Check your configuration.",
            500,
        )

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# STUDENT: VERIFY MOBILE OTP
# ============================================================

@app.route("/verify-mobile-otp", methods=["POST"])
def verify_mobile_otp_route():
    phone = request.form.get("phone", "").strip()
    otp = request.form.get("otp", "").strip()

    if not phone or not otp:
        return json_error("Enter your phone number and OTP.")

    if not valid_phone(phone):
        return json_error("Enter a valid phone number.")

    if session.get("mobile_otp_destination") != phone:
        return json_error(
            "Request a new OTP for this phone number."
        )

    try:
        approved = check_sms_otp(phone, otp)

        if approved:
            session["mobile_verified"] = True
            return jsonify(
                success=True,
                message="Mobile OTP verified successfully.",
            )

        session["mobile_verified"] = False
        return json_error("Incorrect or expired mobile OTP.")

    except TwilioRestException:
        app.logger.exception("Student Twilio verification failed")
        session["mobile_verified"] = False
        return json_error(
            "Twilio could not verify the OTP.",
            400,
        )

    except Exception:
        app.logger.exception("Student mobile verification failed")
        return json_error(
            "Could not verify OTP. Please try again.",
            500,
        )


# ============================================================
# COMPLETE STUDENT SIGNUP
# ============================================================

@app.route("/complete-signup", methods=["POST"])
def complete_signup():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    gender = request.form.get("gender", "").strip()

    college_name = request.form.get("college_name", "").strip()
    enrollment_no = request.form.get("enrollment_no", "").strip()
    degree = request.form.get("degree", "").strip()
    branch = request.form.get("branch", "").strip()
    password = request.form.get("password", "")

    country = request.form.get("country", "").strip()
    state = request.form.get("state", "").strip()
    city = request.form.get("city", "").strip()
    address = request.form.get("address", "").strip()

    required_fields = [
        name,
        email,
        phone,
        college_name,
        enrollment_no,
        degree,
        branch,
        password,
        country,
        state,
        city,
    ]

    if not all(required_fields):
        flash("Please fill in all required fields.", "error")
        return redirect(url_for("signup"))

    if not valid_email(email):
        flash("Enter a valid email address.", "error")
        return redirect(url_for("signup"))

    if not valid_phone(phone):
        flash("Enter a valid phone number with country code.", "error")
        return redirect(url_for("signup"))

    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "error")
        return redirect(url_for("signup"))

    if session.get("email_verified") is not True:
        flash("Please verify your email OTP first.", "error")
        return redirect(url_for("signup"))

    if session.get("mobile_verified") is not True:
        flash("Please verify your mobile OTP first.", "error")
        return redirect(url_for("signup"))

    if session.get("email_otp_destination") != email:
        flash("The verified email does not match.", "error")
        return redirect(url_for("signup"))

    if session.get("mobile_otp_destination") != phone:
        flash("The verified phone number does not match.", "error")
        return redirect(url_for("signup"))

    photo = request.files.get("college_id_photo")

    if not photo or not photo.filename:
        flash("Please upload your college ID photo.", "error")
        return redirect(url_for("signup"))

    if not allowed_file(photo.filename):
        flash("College ID must be JPG, JPEG, or PNG.", "error")
        return redirect(url_for("signup"))

    photo.stream.seek(0, os.SEEK_END)
    photo_size = photo.stream.tell()
    photo.stream.seek(0)

    if photo_size > MAX_FILE_SIZE:
        flash("College ID photo must be 3 MB or smaller.", "error")
        return redirect(url_for("signup"))

    header = photo.stream.read(8)
    photo.stream.seek(0)

    is_png = header.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpeg = header.startswith(b"\xff\xd8\xff")

    if not (is_png or is_jpeg):
        flash("Upload a valid PNG or JPEG image.", "error")
        return redirect(url_for("signup"))

    connection = None
    cursor = None
    saved_photo_path = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT student_id
            FROM students
            WHERE email = %s
               OR phone = %s
               OR enrollment_no = %s
            LIMIT 1
            """,
            (email, phone, enrollment_no),
        )

        if cursor.fetchone():
            flash(
                "Email, phone, or enrollment number is already registered.",
                "error",
            )
            return redirect(url_for("signup"))

        original_name = secure_filename(photo.filename)
        extension = original_name.rsplit(".", 1)[1].lower()
        photo_filename = f"{secrets.token_hex(16)}.{extension}"

        saved_photo_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            photo_filename,
        )

        photo.save(saved_photo_path)

        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO students (
                name,
                email,
                phone,
                gender,
                enrollment_no,
                college_name,
                degree,
                branch,
                college_id_photo,
                password,
                country,
                state,
                city,
                address,
                email_verified,
                phone_verified
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, TRUE, TRUE
            )
            """,
            (
                name,
                email,
                phone,
                gender,
                enrollment_no,
                college_name,
                degree,
                branch,
                photo_filename,
                hashed_password,
                country,
                state,
                city,
                address,
            ),
        )

        new_student_id = cursor.lastrowid
        connection.commit()

        clear_signup_verification()

        session["student_id"] = new_student_id
        session["student_name"] = name

        flash(
            "Welcome to InterviewBridge! Signup successful.",
            "success",
        )
        return redirect(url_for("home"))

    except Error:
        if connection and connection.is_connected():
            connection.rollback()

        if saved_photo_path and os.path.exists(saved_photo_path):
            os.remove(saved_photo_path)

        app.logger.exception("Student signup failed")
        flash(
            "Signup failed. Check your database columns and try again.",
            "error",
        )
        return redirect(url_for("signup"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# STUDENT LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        flash("Enter your email and password.", "error")
        return redirect(url_for("login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT student_id, name, password
            FROM students
            WHERE email = %s
            LIMIT 1
            """,
            (email,),
        )

        student = cursor.fetchone()

        if student and check_password_hash(
            student["password"], password
        ):
            session.clear()
            session["student_id"] = student["student_id"]
            session["student_name"] = student["name"]

            flash(
                f"Welcome to InterviewBridge, {student['name']}!",
                "success",
            )
            return redirect(url_for("home"))

        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    except Error:
        app.logger.exception("Student login failed")
        flash("Unable to log in. Please try again.", "error")
        return redirect(url_for("login"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# ABOUT
# ============================================================

@app.route("/about")
def about():
    return render_template("about.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# ============================================================
# STUDENT PROFILE
# ============================================================

@app.route("/profile")
def profile():
    if not session.get("student_id"):
        flash("Please log in to view your profile.", "error")
        return redirect(url_for("login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                student_id,
                name,
                email,
                phone,
                gender,
                enrollment_no,
                college_name,
                degree,
                branch,
                college_id_photo,
                country,
                state,
                city,
                address,
                email_verified,
                phone_verified,
                created_at
            FROM students
            WHERE student_id = %s
            LIMIT 1
            """,
            (session["student_id"],),
        )

        student = cursor.fetchone()

        if not student:
            session.clear()
            flash(
                "Student account not found. Please log in again.",
                "error",
            )
            return redirect(url_for("login"))

        return render_template("profile.html", student=student)

    except Error:
        app.logger.exception("Could not load student profile")
        flash("Unable to load your profile.", "error")
        return redirect(url_for("home"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ============================================================
# FILE TOO LARGE
# ============================================================

@app.errorhandler(413)
def file_too_large(error):
    flash("The uploaded request is too large.", "error")
    return redirect(url_for("signup"))


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    print(
        "Twilio Account SID loaded:",
        bool(os.getenv("TWILIO_ACCOUNT_SID")),
    )
    print(
        "Twilio Auth Token loaded:",
        bool(os.getenv("TWILIO_AUTH_TOKEN")),
    )
    print(
        "Twilio Verify Service SID loaded:",
        bool(os.getenv("TWILIO_VERIFY_SERVICE_SID")),
    )

    app.run(debug=True)
