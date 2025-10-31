import google.generativeai as genai
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token,jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
from dotenv import load_dotenv
import os
from flask import jsonify
 
from auth import check_login
bcrypt = Bcrypt()

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
client = MongoClient(os.getenv('MONGO_DB'))

db = client[os.getenv('DB_NAME')]
history = db["history"]
def api(file_path: str):
    audio_file = genai.upload_file(file_path)

    model = genai.GenerativeModel(os.getenv("GEMINI_MODEL"))

    prompt = """
You are an expert AI assistant specialized in analyzing meeting recordings, audio discussions, and video content. 
Your job is to take an audio/video transcript and provide a structured, clear, and professional response in ENGLISH ONLY. 
Do NOT use any other language. 
Always keep formatting consistent with headings and bullet points. 
Follow the structure below very strictly:

====================================================================
1. Abstract Summary
   - Provide a short overview (3–5 sentences) of the entire transcript.
   - Keep it professional and concise.
   - Avoid repetition. Focus on the purpose and main discussion.

2. Key Points
   - Extract the most important points from the transcript.
   - Present them in clear bullet points.
   - Each point should be precise, capturing essential details.
   - Do not add unnecessary details, only the key information.

3. Action Items
   - List clear, concise, and actionable tasks derived from the discussion.
   - Use numbered format (1, 2, 3, …).
   - Each action should be written as a direct instruction.
   - Make sure action items are practical and easy to follow.

4. Sentiment Analysis
   - Identify the overall sentiment of the discussion: Positive, Neutral, or Negative.
   - Briefly explain WHY you selected that sentiment (1–2 lines).
   - Keep explanation factual and objective, not opinionated.

5. Proper Transcript
   - Provide the cleaned, readable version of the transcript.
   - Remove filler words (uh, um, like, you know).
   - Ensure proper grammar, punctuation, and readability.
   - Keep original meaning intact, but make it professional.

====================================================================
Rules:
- Response MUST always follow the above format.
- Never skip a section, even if content is missing.
- Always keep the output well-formatted with headings and spacing.
- Output should look neat and professional, similar to a business meeting summary.
"""


    res = model.generate_content(
        [prompt, audio_file],
        generation_config=genai.types.GenerationConfig(
            temperature=1,          # creativity level (0 = strict, 1 = creative)
            max_output_tokens=4000,    # response length limit 
        )
    )

    return save_history(res)
def save_history(res):
    login_status = check_login()  # call the function
    user_data = login_status.get_json()  # extract JSON
    if user_data.get("logged_in"):
        user_id = user_data.get("user_id")
        history.insert_one({
            "user_id": user_id,
            "history": res.text,
            "created_at": datetime.datetime.utcnow()
        })
        return ({"message":"history saved", "resp": res.text})
    else :
        return ({
            "response" : res.text
        })
def delete_single_history(history_id):
    # Check if history exists
    history_data = history.find_one({"_id": ObjectId(history_id)})
    
    if history_data:
        history.delete_one({"_id": ObjectId(history_id)})  # Correct method
        return "history deleted"
    else:
        return {"id":history_id}
def get_history(user_id) :
  history_Data =  history.find({"user_id":user_id})
  if history_Data :
    record=[]
    for records in history_Data :
      records["_id"] = str(records["_id"])
      record.append(records)


    return {"history_record": record}
  else :
      return "Sorry! No record Available"
  
def delete_all_history(user_id):
    # """
    # Deletes all history documents for a specific user.
    
    # :param user_id: ID of the logged-in user
    # :return: message indicating how many records were deleted
    # """
    # Delete all history entries for the user
    result = history.delete_many({"user_id": user_id})
    
    if result.deleted_count > 0:
        return f"{result.deleted_count} history entries deleted"
    else:
        return "no history found of user"


def delete_multiple_history(history_ids):
    # """
    # Deletes multiple history entries based on a list of history IDs.
    
    # :param history_ids: list of history_id strings
    # :return: message indicating how many were deleted
    # """
    # Convert all IDs to ObjectId
    obj_ids = [ObjectId(h_id) for h_id in history_ids]

    result = history.delete_many({"_id": {"$in": obj_ids}})
    
    if result.deleted_count > 0:
        return f"{result.deleted_count} history entries deleted"
    else:
        return "no history found for the selected entries"