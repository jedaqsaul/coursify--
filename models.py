from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model, SerializerMixin):
    __tablename__ = 'user'

    serialize_rules = (
        '-password_hash',
        '-enrollments.user',
        '-courses.instructor',
        '-reviews.user',
        '-password_history.user'
    )

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    courses = db.relationship('Course', back_populates='instructor', cascade="all, delete-orphan")
    enrollments = db.relationship('Enrollment', back_populates='user', cascade="all, delete-orphan")
    reviews = db.relationship('Review', back_populates='user', cascade="all, delete-orphan")
    password_history = db.relationship('PasswordHistory', back_populates='user', cascade="all, delete-orphan")

    def set_password(self, password):
        if self.password_hash:
            history = PasswordHistory(user_id=self.id, old_password_hash=self.password_hash)
            db.session.add(history)
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "age": self.age,
            "gender": self.gender,
            "email": self.email,
            "role": self.role
        }


class Course(db.Model, SerializerMixin):
    __tablename__ = 'courses'

    serialize_rules = (
        '-instructor.courses',
        '-reviews.course',
    )

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(20), nullable=False)
    lesson_count = db.Column(db.Integer, nullable=False)

    instructor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    instructor = db.relationship('User', back_populates='courses')

    reviews = db.relationship('Review', back_populates='course', cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "duration": self.duration,
            "level": self.level,
            "lesson_count": self.lesson_count,
            "instructor": {
                "first_name": self.instructor.first_name,
                "last_name": self.instructor.last_name,
                "email": self.instructor.email
            },
            "reviews": [review.to_dict() for review in self.reviews]
        }


class Enrollment(db.Model, SerializerMixin):
    __tablename__ = 'enrollment'

    serialize_rules = ('-user.enrollments',)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    progress = db.Column(db.String, default="0.0")
    review_score = db.Column(db.Integer, nullable=True)
    certificate_issued = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='enrollments')
    course = db.relationship('Course')  # Added for reverse access

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "course_id": self.course_id,
            "enrollment_date": self.enrollment_date.isoformat(),
            "progress": self.progress,
            "review_score": self.review_score,
            "certificate_issued": self.certificate_issued
        }


class Review(db.Model, SerializerMixin):
    __tablename__ = 'review'

    serialize_rules = (
        '-user.reviews',
        '-course.reviews',
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    comment = db.Column(db.Text, nullable=True)

    user = db.relationship('User', back_populates='reviews')
    course = db.relationship('Course', back_populates='reviews')

    def to_dict(self):
        return {
            "id": self.id,
            "rating": self.rating,
            "comment": self.comment,
            "user": {
                "username": f"{self.user.first_name} {self.user.last_name}"
            }
        }


class PasswordHistory(db.Model, SerializerMixin):
    __tablename__ = 'password_history'

    serialize_rules = ('-user.password_history',)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    old_password_hash = db.Column(db.String(128), nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', back_populates='password_history')
