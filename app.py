from flask import Flask,  jsonify, request, make_response
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy

from sqlalchemy import  text
from werkzeug.security import generate_password_hash, check_password_hash
from functions import serialize_row

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
                              email VARCHAR(50), password VARCHAR(256) )"""))
      db.session.commit()
        


### RESSOURCES 

class User_data(Resource):
   @jwt_required()
   def get(self, id):
      
      stmt = text("""SELECT id, email, password FROM users WHERE id = :id""")
      user_data = db.session.execute(stmt, {'id': id}).fetchone()

      
      if user_data:
        username = user_data.email 
        return jsonify({"username": username })      #Ignore when 200
      else:
         return {'message': 'Error'}, 404


class Btc(Resource):
  
  def get(self):

    rows = db.session.execute(text("SELECT * FROM bitcoin_data")).mappings().all()
    clean = [dict(row) for row in rows]
    return jsonify({"content": clean})


api.add_resource(User_data, '/api/users/<int:id>')
api.add_resource(Btc, '/api/bitcoin')



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

    if not username or not password:
       
       return jsonify({"message": "Username and password required"}), 400
    
    hashed_password = generate_password_hash(password)
    
    stmt = text("INSERT INTO users (email, password) VALUES (:email, :password)")
    db.session.execute(stmt, {"email": username, "password": hashed_password})
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
    
    smtm = text((f"SELECT id, email, password FROM users WHERE email = :username"))
    query = db.session.execute(smtm, {"username": username}).fetchone()
    
    
    if not query:
       
       return jsonify({"message": "User not found"}), 404
    
    hashed_password = query.password
    if check_password_hash(hashed_password, password):
       
       id = query.id
       access_token = create_access_token(identity=username, expires_delta=exp)
     
       message = {"message": "Login successful!", "access_token": access_token, "user_id": id}
       response = make_response(jsonify(message))
       return response
        
    else:
       return {"message": "Invalid password"}, 401
    
   except Exception as e:
       return {"message": "An error occured", 'error': str(e)}, 500
   


### MAIN APP

if __name__ == "__main__":

  app.run(debug=False)




