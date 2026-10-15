
from flask import Flask, render_template, session
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

# MySQL database configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root",
    "database": "InterviewBridge"
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


@app.route("/")
def home():
    db_connected = False
    interviewer = None
    upcoming_interview = None

    try:
        connection = get_db_connection()
        db_connected = connection.is_connected()

        cursor = connection.cursor(dictionary=True)

        # Get the latest interview and interviewer information
        cursor.execute("""
            SELECT
                i.interview_id,
                i.interview_type,
                i.domain,
                i.scheduled_at,
                i.status,
                iv.name AS interviewer_name,
                iv.company,
                iv.job_role
            FROM interviews i
            LEFT JOIN interviewers iv
                ON i.interviewer_id = iv.interviewer_id
            WHERE i.status = 'Scheduled'
            ORDER BY i.scheduled_at ASC
            LIMIT 1
        """)

        upcoming_interview = cursor.fetchone()

        if upcoming_interview:
            interviewer = {
                "name": upcoming_interview["interviewer_name"],
                "company": upcoming_interview["company"],
                "role": upcoming_interview["job_role"]
            }

        cursor.close()
        connection.close()

    except Error as error:
        print("MySQL connection error:", error)

    return render_template(
        "index.html",
        db_connected=db_connected,
        interviewer=interviewer,
        upcoming_interview=upcoming_interview
    )

@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/signup")
def signup():
    return render_template("signup.html")


if __name__ == "__main__":
    app.run(debug=True)
