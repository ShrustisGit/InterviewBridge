CREATE DATABASE InterviewBridge;

USE InterviewBridge;

CREATE TABLE students (
    student_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    college VARCHAR(150),
    degree VARCHAR(100),
    branch VARCHAR(100),
    graduation_year INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE resumes (
    resume_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES students(student_id)
        ON DELETE CASCADE
);

CREATE TABLE resume_reviews (
    review_id INT AUTO_INCREMENT PRIMARY KEY,
    resume_id INT NOT NULL,

    ats_score DECIMAL(5,2),
    skills_score DECIMAL(5,2),
    education_score DECIMAL(5,2),
    project_score DECIMAL(5,2),
    overall_score DECIMAL(5,2),

    extracted_skills TEXT,
    strengths TEXT,
    weaknesses TEXT,
    suggestions TEXT,

    reviewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (resume_id)
        REFERENCES resumes(resume_id)
        ON DELETE CASCADE
);


CREATE TABLE interviewers (
    interviewer_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    company VARCHAR(150),
    job_role VARCHAR(100),
    experience_years INT,
    specialization VARCHAR(200),
    bio TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);



CREATE TABLE interviews (
    interview_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    interviewer_id INT,
    resume_id INT,

    interview_type ENUM('AI', 'EXPERT', 'HYBRID') NOT NULL,
    domain VARCHAR(100),
    scheduled_at DATETIME,
    started_at DATETIME,
    completed_at DATETIME,

    status ENUM(
        'Scheduled',
        'In Progress',
        'Completed',
        'Cancelled'
    ) DEFAULT 'Scheduled',

    FOREIGN KEY (student_id)
        REFERENCES students(student_id)
        ON DELETE CASCADE,

    FOREIGN KEY (interviewer_id)
        REFERENCES interviewers(interviewer_id)
        ON DELETE SET NULL,

    FOREIGN KEY (resume_id)
        REFERENCES resumes(resume_id)
        ON DELETE SET NULL
);


CREATE TABLE interview_questions (
    question_id INT AUTO_INCREMENT PRIMARY KEY,
    interview_id INT NOT NULL,
    question_text TEXT NOT NULL,
    question_type VARCHAR(50),
    question_order INT,

    FOREIGN KEY (interview_id)
        REFERENCES interviews(interview_id)
        ON DELETE CASCADE
);

CREATE TABLE interview_answers (
    answer_id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT NOT NULL,
    student_id INT NOT NULL,

    answer_text TEXT,
    audio_path VARCHAR(500),
    video_path VARCHAR(500),
    response_time_seconds INT,

    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (question_id)
        REFERENCES interview_questions(question_id)
        ON DELETE CASCADE,

    FOREIGN KEY (student_id)
        REFERENCES students(student_id)
        ON DELETE CASCADE
);


CREATE TABLE expert_reviews (
    expert_review_id INT AUTO_INCREMENT PRIMARY KEY,
    interview_id INT NOT NULL,
    interviewer_id INT NOT NULL,

    technical_score DECIMAL(5,2),
    communication_score DECIMAL(5,2),
    problem_solving_score DECIMAL(5,2),
    confidence_score DECIMAL(5,2),
    overall_score DECIMAL(5,2),

    comments TEXT,
    improvement_suggestions TEXT,

    reviewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (interview_id)
        REFERENCES interviews(interview_id)
        ON DELETE CASCADE,

    FOREIGN KEY (interviewer_id)
        REFERENCES interviewers(interviewer_id)
        ON DELETE CASCADE
);


CREATE TABLE progress (
    progress_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    interview_id INT NOT NULL,

    technical_score DECIMAL(5,2),
    communication_score DECIMAL(5,2),
    confidence_score DECIMAL(5,2),
    overall_score DECIMAL(5,2),

    improvement_percentage DECIMAL(5,2),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES students(student_id)
        ON DELETE CASCADE,

    FOREIGN KEY (interview_id)
        REFERENCES interviews(interview_id)
        ON DELETE CASCADE
);


