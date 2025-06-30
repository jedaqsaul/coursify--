from flask_restful import Resource
from flask import request
from models import db, User
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import jwt_required, get_jwt_identity


class UserList(Resource):
    def get(self):
        try:
            users = User.query.all()
            return [user.to_dict() for user in users], 200
        except Exception as e:
            return {"error": f"Failed to fetch users: {str(e)}"}, 500

    def post(self):
        data = request.get_json()
        required = ('first_name', 'last_name', 'age', 'gender', 'email', 'role', 'password')
        
        # Validation
        if not data or not all(k in data for k in required):
            return {"error": "Missing required fields"}, 400

        if User.query.filter_by(email=data['email']).first():
            return {"error": "Email already exists"}, 400

        try:
            new_user = User(
                first_name=data['first_name'],
                last_name=data['last_name'],
                age=data['age'],
                gender=data['gender'],
                email=data['email'],
                role=data['role'],
                password_hash=generate_password_hash(data['password'])
            )
            db.session.add(new_user)
            db.session.commit()
            return new_user.to_dict(), 201
        except SQLAlchemyError as e:
            db.session.rollback()
            return {"error": f"Database error: {str(e)}"}, 500
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}, 500


class UserById(Resource):
    @jwt_required()
    def get(self, user_id):
        current_user_id = get_jwt_identity()
        if user_id != current_user_id:
            return {"error": "Unauthorized access."}, 403

        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        return user.to_dict(), 200

    @jwt_required()
    def patch(self, user_id):
        current_user_id = get_jwt_identity()
        if user_id != current_user_id:
            return {"error": "Unauthorized access."}, 403

        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404

        data = request.get_json()
        for field in ['first_name', 'last_name', 'age', 'gender', 'email', 'role']:
            if field in data:
                setattr(user, field, data[field])

        if 'password' in data:
            user.set_password(data['password'])

        db.session.commit()
        return user.to_dict(), 200

    @jwt_required()
    def delete(self, user_id):
        current_user_id = get_jwt_identity()
        if user_id != current_user_id:
            return {"error": "Unauthorized access."}, 403

        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404

        db.session.delete(user)
        db.session.commit()
        return {"message": f"User with id {user_id} has been deleted"}, 200



def register_user_routes(api):
    api.add_resource(UserList, '/users')
    api.add_resource(UserById, '/users/<int:user_id>')
