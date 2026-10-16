
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

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)
from werkzeug.utils import secure_filename


# -------------------- ENVIRONMENT CONFIG --------------------

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "change-this-development-secret",
)


# -------------------- DATABASE CONFIG --------------------

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "root"),
    "database": os.getenv("DB_NAME", "InterviewBridge"),
}


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# -------------------- UPLOAD CONFIG --------------------

# Absolute path: InterviewBridge/static/uploads/college_ids
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
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# -------------------- EMAIL OTP CONFIG --------------------

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
        record["otp"], submitted_otp.strip()
    ):
        record["attempts"] += 1
        return False, "Incorrect OTP."

    otp_store.pop(key, None)
    return True, "Email OTP verified successfully."


# -------------------- SEND EMAIL OTP --------------------

def send_email_otp(email, otp):
    mail_username = os.getenv("MAIL_USERNAME")
    mail_password = os.getenv("MAIL_PASSWORD")

    mail_server = os.getenv(
        "MAIL_SERVER", "smtp.gmail.com"
    )
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

    with smtplib.SMTP(
        mail_server, mail_port, timeout=20
    ) as smtp:
        smtp.starttls()
        smtp.login(mail_username, mail_password)
        smtp.send_message(message)


# -------------------- TWILIO VERIFY CONFIG --------------------

def get_twilio_client():
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")

    if not account_sid or not auth_token:
        raise ValueError(
            "Twilio Account SID or Auth Token is missing in .env"
        )

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


# -------------------- HOME --------------------

@app.route("/")
def home():
    return render_template("index.html")


# -------------------- SIGNUP PAGE --------------------

@app.route("/signup", methods=["GET"])
def signup():
    return render_template("signup.html")


# -------------------- SEND EMAIL OTP --------------------

@app.route("/send-email-otp", methods=["POST"])
def send_email_otp_route():
    email = request.form.get(
        "email", ""
    ).strip().lower()

    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        return jsonify(
            success=False,
            message="Enter a valid email address.",
        ), 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT student_id FROM students WHERE email = %s",
            (email,),
        )

        if cursor.fetchone():
            return jsonify(
                success=False,
                message="This email is already registered.",
            ), 409

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
        app.logger.exception("Could not send email OTP")

        return jsonify(
            success=False,
            message=(
                "Could not send email OTP. "
                "Check your email settings and try again."
            ),
        ), 500

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


# -------------------- VERIFY EMAIL OTP --------------------

@app.route("/verify-email-otp", methods=["POST"])
def verify_email_otp_route():
    email = request.form.get(
        "email", ""
    ).strip().lower()

    otp = request.form.get("otp", "").strip()

    if not email or not otp:
        return jsonify(
            success=False,
            message="Enter your email and OTP.",
        ), 400

    if session.get("email_otp_destination") != email:
        return jsonify(
            success=False,
            message="Request a new OTP for this email address.",
        ), 400

    success, message = verify_otp("email", email, otp)

    if success:
        session["email_verified"] = True

        return jsonify(
            success=True,
            message=message,
        )

    return jsonify(
        success=False,
        message=message,
    ), 400


# -------------------- SEND MOBILE OTP --------------------

@app.route("/send-mobile-otp", methods=["POST"])
def send_mobile_otp_route():
    phone = request.form.get(
        "phone", ""
    ).strip()

    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        return jsonify(
            success=False,
            message=(
                "Enter a valid phone number with country code, "
                "for example +919876543210."
            ),
        ), 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT student_id FROM students WHERE phone = %s",
            (phone,),
        )

        if cursor.fetchone():
            return jsonify(
                success=False,
                message="This phone number is already registered.",
            ), 409

        status = send_sms_otp(phone)

        session["mobile_verified"] = False
        session["mobile_otp_destination"] = phone

        app.logger.info(
            "Twilio Verify request accepted with status: %s",
            status,
        )

        return jsonify(
            success=True,
            message="Mobile OTP sent successfully.",
        )

    except TwilioRestException as error:
        app.logger.error(
            "Twilio send OTP error: code=%s, status=%s",
            error.code,
            error.status,
        )

        return jsonify(
            success=False,
            message=(
                "Twilio could not send the OTP. Check your "
                "Verify Service, trial restrictions, and phone number."
            ),
        ), 400

    except Exception:
        app.logger.exception("Could not send mobile OTP")

        return jsonify(
            success=False,
            message=(
                "Could not send mobile OTP. "
                "Check your configuration and database."
            ),
        ), 500

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


# -------------------- VERIFY MOBILE OTP --------------------

@app.route("/verify-mobile-otp", methods=["POST"])
def verify_mobile_otp_route():
    phone = request.form.get(
        "phone", ""
    ).strip()

    otp = request.form.get(
        "otp", ""
    ).strip()

    if not phone or not otp:
        return jsonify(
            success=False,
            message="Enter your phone number and OTP.",
        ), 400

    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        return jsonify(
            success=False,
            message="Enter a valid phone number with country code.",
        ), 400

    if session.get("mobile_otp_destination") != phone:
        return jsonify(
            success=False,
            message="Request a new OTP for this phone number.",
        ), 400

    try:
        approved = check_sms_otp(phone, otp)

        if approved:
            session["mobile_verified"] = True

            return jsonify(
                success=True,
                message="Mobile OTP verified successfully.",
            )

        session["mobile_verified"] = False

        return jsonify(
            success=False,
            message="Incorrect or expired OTP.",
        ), 400

    except TwilioRestException as error:
        app.logger.warning(
            "Twilio verification error: code=%s, status=%s",
            error.code,
            error.status,
        )

        if error.code in (20404, 60200, 60202, 60203):
            session["mobile_verified"] = False

            return jsonify(
                success=False,
                message="OTP is invalid or expired. Request a new one.",
            ), 400

        return jsonify(
            success=False,
            message=(
                "Twilio could not verify the OTP. "
                "Check your Verify Service configuration."
            ),
        ), 400

    except Exception:
        app.logger.exception("Mobile OTP verification failed")

        return jsonify(
            success=False,
            message="Could not verify the OTP. Please try again.",
        ), 500


# -------------------- COMPLETE STUDENT SIGNUP --------------------

@app.route("/complete-signup", methods=["POST"])
def complete_signup():
    name = request.form.get("name", "").strip()
    email = request.form.get(
        "email", ""
    ).strip().lower()

    phone = request.form.get("phone", "").strip()
    gender = request.form.get("gender", "").strip()

    college_name = request.form.get(
        "college_name", ""
    ).strip()

    enrollment_no = request.form.get(
        "enrollment_no", ""
    ).strip()

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

    if len(password) < 8:
        flash(
            "Password must contain at least 8 characters.",
            "error",
        )
        return redirect(url_for("signup"))

    # Verify that the submitted email and phone were verified.
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
        flash(
            "College ID must be a JPG, JPEG, or PNG image.",
            "error",
        )
        return redirect(url_for("signup"))

    # Check actual uploaded size.
    photo.stream.seek(0, os.SEEK_END)
    photo_size = photo.stream.tell()
    photo.stream.seek(0)

    if photo_size > MAX_FILE_SIZE:
        flash(
            "College ID photo must be 3 MB or smaller.",
            "error",
        )
        return redirect(url_for("signup"))

    # Check PNG/JPEG file signature.
    header = photo.stream.read(8)
    photo.stream.seek(0)

    is_png = header.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpeg = header.startswith(b"\xff\xd8\xff")

    if not (is_png or is_jpeg):
        flash(
            "The uploaded file is not a valid PNG or JPEG image.",
            "error",
        )
        return redirect(url_for("signup"))

    connection = None
    cursor = None
    saved_photo_path = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT student_id
            FROM students
            WHERE email = %s
               OR phone = %s
               OR enrollment_no = %s
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

        # Generate a unique filename.
        photo_filename = (
            f"{secrets.token_hex(16)}.{extension}"
        )

        # Save inside static/uploads/college_ids/
        saved_photo_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            photo_filename,
        )

        photo.save(saved_photo_path)

        hashed_password = generate_password_hash(password)

        # NOTE: college_name has its own column and placeholder.
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
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s,
                TRUE, TRUE
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

        # Capture the new student's ID before closing the cursor.
        new_student_id = cursor.lastrowid

        connection.commit()

        # Clear OTP verification state after successful signup.
        session.pop("email_verified", None)
        session.pop("mobile_verified", None)
        session.pop("email_otp_destination", None)
        session.pop("mobile_otp_destination", None)

        # Automatically log in the new student.
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

        # Remove the saved photo if database insertion fails.
        if saved_photo_path and os.path.exists(saved_photo_path):
            os.remove(saved_photo_path)

        app.logger.exception("Student signup failed")

        flash(
            "Signup failed. Check your database and try again.",
            "error",
        )
        return redirect(url_for("signup"))

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get(
        "email", ""
    ).strip().lower()

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
        app.logger.exception("Login failed")

        flash(
            "Unable to log in right now. Please try again.",
            "error",
        )
        return redirect(url_for("login"))

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


# -------------------- ABOUT --------------------

@app.route("/about")
def about():
    return render_template("about.html")


# -------------------- LOGOUT --------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# -------------------- STUDENT PROFILE --------------------

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

        # Include college_name in the profile data.
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

        return render_template(
            "profile.html",
            student=student,
        )

    except Error:
        app.logger.exception("Could not load student profile.")

        flash(
            "Unable to load your profile. Please try again.",
            "error",
        )
        return redirect(url_for("home"))

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


# -------------------- FILE TOO LARGE --------------------

@app.errorhandler(413)
def file_too_large(error):
    flash(
        "The uploaded file exceeds the 3 MB limit.",
        "error",
    )
    return redirect(url_for("signup"))


# -------------------- RUN APP --------------------

if __name__ == "__main__":
    # Print only whether the environment variables are configured.
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
