from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api, bcrypt
from models import User, Recipe

class Signup(Resource):
    def post(self):
        # Get data from request
        data = request.get_json()

        # Extract user data
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        # Check if username and password are provided
        if not username or not password:
            return jsonify({'error': 'Username and password are required.'}), 400  # Change status code to 400

        # Hash the password
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')

        # Create a new user with hashed password
        new_user = User(username=username, password_hash=password_hash, image_url=image_url, bio=bio)

        # Add the new user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Username already exists.'}), 409  # Change status code to 409

        # Set user_id in session
        session['user_id'] = new_user.id

        # Return user data
        return new_user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        # Check if user_id is in session (logged in)
        user_id = session.get('user_id')
        if user_id:
            # Retrieve user from the database
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200  # Return user details with status code 200
            else:
                return jsonify({'error': 'User not found.'}), 404  # User not found
        else:
            return jsonify({'error': 'Unauthorized'}), 401  # Unauthorized

class Login(Resource):
    def post(self):
        # Get data from request
        data = request.get_json()

        # Extract username and password from request data
        username = data.get('username')
        password = data.get('password')

        # Check if username and password are provided
        if not username or not password:
            return jsonify({'error': 'Username and password are required.'}), 400

        # Query the database for the user with the provided username
        user = User.query.filter_by(username=username).first()

        # If user exists and password is correct, authenticate
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Save user ID in session
            session['user_id'] = user.id

            # Return user data
            return user.to_dict(), 200
        else:
            # If authentication fails, return error message
            return jsonify({'error': 'Invalid username or password.'}), 401


class Logout(Resource):
    def delete(self):
        # Check if user is logged in (user_id is in session)
        if 'user_id' in session:
            # Remove user_id from session
            session.pop('user_id')

            # Return empty response with status code 204
            return '', 204
        else:
            # If user is not logged in, return error message with status code 401
            return jsonify({'error': 'Unauthorized'}), 401

class RecipeIndex(Resource):
    def get(self):
        # Check if user is logged in (user_id is in session)
        if 'user_id' in session:
            # Query all recipes from the database
            recipes = Recipe.query.all()

            # Serialize recipes to JSON
            recipe_list = [recipe.to_dict() for recipe in recipes]

            # Return recipes with status code 200
            return jsonify(recipe_list), 200
        else:
            # If user is not logged in, return error message with status code 401
            return jsonify({'error': 'Unauthorized'}), 401
        
    def post(self):
        # Check if user is logged in (user_id is in session)
        if 'user_id' in session:
            # Get data from request
            data = request.get_json()

            # Extract recipe data
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            # Validate recipe data
            errors = []
            if not title:
                errors.append('Title is required.')
            if not instructions:
                errors.append('Instructions are required.')
            if not minutes_to_complete:
                errors.append('Minutes to complete is required.')
            if errors:
                return jsonify({'errors': errors}), 422

            # Get user ID from session
            user_id = session['user_id']

            # Create a new recipe
            new_recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete, user_id=user_id)

            # Add the new recipe to the database
            db.session.add(new_recipe)
            db.session.commit()

            # Return recipe data
            return new_recipe.to_dict(), 201
        else:
            # If user is not logged in, return error message with status code 401
            return jsonify({'error': 'Unauthorized'}), 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
