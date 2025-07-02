from flask import Flask,  jsonify, request, make_response
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy

from sqlalchemy import  text
from werkzeug.security import generate_password_hash, check_password_hash


import secrets
import datetime
import os


## KEYS AND CONFIG

secure_key = secrets.token_hex(32)
exp = datetime.timedelta(hours=1)


PGHOST=os.getenv("PGHOST")
PGPORT=os.getenv("PGPORT")
PGUSER=os.getenv("PGUSER")
PGDATABASE=os.getenv("PGDATABASE")
PGPASSWORD=os.getenv("PGPASSWORD") 


url = f"postgresql+psycopg2://{PGUSER}:{PGPASSWORD}@{PGHOST}:{PGPORT}/{PGDATABASE}"


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = url
app.config["JWT_SECRET_KEY"] = f"{secure_key}"


### APP INIT

db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True)


### DATABASE INIT

with app.app_context():


      db.session.execute(text("""CREATE TABLE IF NOT EXISTS 
                              users (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, 
                              email VARCHAR(50), password VARCHAR(256), username VARCHAR(30))"""))
      db.session.commit()
        


### RESSOURCES 

class User_data(Resource):
   @jwt_required()
   def get(self):
      identity = get_jwt_identity()

      stmt = text("""SELECT username, email, password FROM users WHERE username = :username""")
      user_data = db.session.execute(stmt, {'username': identity}).fetchone()

      if user_data:
        username = user_data.username 
        email = user_data.email
        return jsonify({"username": username, "email": email })
      
      else:
         return {'message': 'Error'}, 404

class Password_change(Resource):
   @jwt_required()
   def post(self):
      identity = get_jwt_identity()

      data = request.get_json()
      new_password = data['new_password']
      old_password = data['old_password']

      stmt = text("""SELECT username, password FROM users WHERE username = :username""")
      user_data = db.session.execute(stmt, {'username': identity}).fetchone()

      if check_password_hash(user_data.password, old_password):
         user_data.password = generate_password_hash(new_password)
         db.session.commit()

         response = make_response(jsonify({'message': 'Password updated !'}))
         return response
      
      else:
         response = make_response(jsonify({'Error': "Your password is incorrect"})), 404
         return response


class Btc(Resource):
  
  def get(self):

    rows = db.session.execute(text("SELECT * FROM bitcoin_data")).mappings().all()
    clean = [dict(row) for row in rows]
    return jsonify({"content": clean})


api.add_resource(User_data, '/api/users/')
api.add_resource(Btc, '/api/bitcoin')
api.add_resource(Password_change, '/change/password' )


### ROUTES

@app.route('/debug', methods=['GET'])
@jwt_required()
def debug_auth():
    auth_header = request.headers.get("Authorization", "").strip()
    current_user = get_jwt_identity()
    print("Received Header:", auth_header)
    print("Extracted User from JWT:", current_user)
    return jsonify({
        "received_header": auth_header,
        "extracted_user": current_user
    })


@app.route('/api/sign-up', methods=['POST'])
def register():

  try:

    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']

    if not username or not password or not email:
       
       return jsonify({"message": "Username and password required"}), 400
    
    hashed_password = generate_password_hash(password)
    
    stmt = text("INSERT INTO users (email, password, username) VALUES (:email, :password, :username)")
    db.session.execute(stmt, {"email": email, "password": hashed_password, "username": username})
    db.session.commit()
    
    response = make_response(jsonify({'message': 'Registration complete'}))
    return response
 

  except Exception as e:
    return jsonify({"message": "Something went wrong with your request", "error": str(e)}), 500



@app.route('/api/sign-in', methods=['POST'])
def authenticate():
   
   try:

    data = request.get_json()
    username = data['username']
    password = data['password']
    
    smtm = text((f"SELECT password FROM users WHERE username = :username"))
    query = db.session.execute(smtm, {"username": username}).fetchone()
    
    
    if not query:
       
       return jsonify({"message": "User not found"}), 404
    
    hashed_password = query.password
    if check_password_hash(hashed_password, password):
       
       
       access_token = create_access_token(identity=username, expires_delta=exp)
     
       message = {"message": "Login successful!", "access_token": access_token}
       response = make_response(jsonify(message))
       return response
        
    else:
       return {"message": "Invalid password"}, 401
    
   except Exception as e:
       return {"message": "An error occured", 'error': str(e)}, 500
   


### MAIN APP

if __name__ == "__main__":

  app.run(debug=False)




