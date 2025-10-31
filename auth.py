from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token,jwt_required, get_jwt_identity,verify_jwt_in_request
from flask import Flask,jsonify,session
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
from dotenv import load_dotenv
from flask_session import Session
import os
bcrypt = Bcrypt()
app = Flask(__name__)

load_dotenv() 
app.config["SESSION_PERMANENT"] = True
# MongoDB connection
client = MongoClient("mongodb+srv://rajeelsiddiqui3_db_user:rajeel321@cluster0.rtiuzsa.mongodb.net/")
db = client["TextToTalk_PRO"]
users = db["users"]

# ---------- Register ----------
def register_user(firstname, lastname, email, password):
    # Check if user already exists
    if users.find_one({"email": email}):
        return {"error": "User already exists"}, 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    user = {
        "firstname": firstname,
        "lastname": lastname,
        "email": email,
        "password": hashed_pw,
        "created_at": datetime.datetime.utcnow()
    }
    users.insert_one(user)
    return {"message": "User registered successfully"}, 201

# ---------- Login ----------
def login_user(email, password):
    user = users.find_one({"email": email})
    if not user or not bcrypt.check_password_hash(user["password"], password):
        return {"error": "Invalid email or password"}, 401

    token = create_access_token(identity=str(user["_id"]))
    
    return {"token": token, "message": "Login successful","user": {
        "user_id": str(user["_id"]),
        "firstname": user["firstname"]
    }}, 200

# ---------- Profile ----------
def get_profile(user_id):
    user = users.find_one({"_id": ObjectId(user_id)}, {"password": 0})
    if not user:
        return {"error": "User not found"}, 404
    user["_id"] = str(user["_id"])
    return {"user": user}, 200

# ---------- Edit Profile ----------
def edit_profile(user_id, data):
    update_data = {}
    if "firstname" in data:
        update_data["firstname"] = data["firstname"]
    if "lastname" in data:
        update_data["lastname"] = data["lastname"]
    if "email" in data:
        update_data["email"] = data["email"]

    if not update_data:
        return {"error": "No fields to update"}, 400

    users.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
    return {"message": "Profile updated successfully"}, 200


def check_login():
    try:
        # Verify JWT from request
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        return jsonify({"logged_in": True, "user_id": user_id})
    except Exception:
        return jsonify({"logged_in": False, "user_id": None})
    
def logout_user():
    # Since JWT is stateless, we can't "invalidate" it on server side
    # Best approach: tell frontend to delete token from storage
    session.clear()  # clear server-side session if using Flask-Session
    return {"message": "Logged out successfully"}, 200