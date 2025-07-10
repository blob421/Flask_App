from flask import Flask,  jsonify, request, make_response
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import set_access_cookies, set_refresh_cookies, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import datetime

import os

from models import Users, UserApi, CryptoApi, db


## KEYS AND CONFIG

secure_key = secrets.token_hex(32)


PGHOST=os.getenv("PGHOST")
PGPORT=os.getenv("PGPORT")
PGUSER=os.getenv("PGUSER")
PGDATABASE=os.getenv("PGDATABASE")
PGPASSWORD=os.getenv("PGPASSWORD") 


url = f"postgresql+psycopg2://{PGUSER}:{PGPASSWORD}@{PGHOST}:{PGPORT}/{PGDATABASE}"


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = url
app.config["JWT_SECRET_KEY"] = f"{secure_key}"
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True 
app.config['JWT_COOKIE_SAMESITE'] = 'None'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
### APP INIT


api = Api(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True, origins=['gentle-pond-0eb439910.2.azurestaticapps.net'])



### DATABASE INIT
db.init_app(app)

with app.app_context():
 db.create_all()


### RESSOURCES 

class User_data(Resource):
   @jwt_required()
   def get(self):
      identity = get_jwt_identity()

      api = UserApi()
      user_data = api.get_by_username(identity)

      if user_data:
        username = user_data.username 
        email = user_data.email
        return jsonify({"username": username, "email": email })
      
      else:
         return {'message': 'Error'}, 404



class Btc(Resource):
  
  def get(self):
    api = CryptoApi()
    rows = api.get_all()
    clean = [row.serialize() for row in rows]
    return jsonify({"content": clean})


api.add_resource(User_data, '/api/users/')
api.add_resource(Btc, '/api/bitcoin')



### ROUTES
@app.route('/api/refresh_token', methods = ['POST'])
@jwt_required(refresh=True)
def issue_new_token():
   
   identity = get_jwt_identity()
   if identity:
      
      response = jsonify({'msg': 'Issued a new access token'})
      new_token = create_access_token(identity=identity)
      set_access_cookies(response, new_token, max_age=60 * 15)
      return response
   else:
      return jsonify({'error': 'user needs to be logged in'}), 401


@app.route('/api/check-auth', methods = ['GET'])
@jwt_required()
def is_auth():
   
   return jsonify({'authenticated': True}), 200



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
    new_user = Users(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    response = make_response(jsonify({'message': 'Registration complete'}))
    return response
 

  except Exception as e:
    return jsonify({"message": "Something went wrong with your request", "error": str(e)}), 500



@app.route('/api/sign-in', methods=['POST'])
def authenticate():
   
   try:

    data = request.get_json()
    identity = data['username']
    password = data['password']

    api = UserApi()
    user_data = api.get_by_username(identity)
    
    if not user_data:
       
       return jsonify({"message": "User not found"}), 404
    
    hashed_password = user_data.password
    if check_password_hash(hashed_password, password):
       
       
       access_token = create_access_token(identity=identity)
       refresh_token = create_refresh_token(identity=identity)
       message = {"message": "Login successful!"}
       response = make_response(jsonify(message))
       set_access_cookies(response, access_token, max_age=60 * 15)
       set_refresh_cookies(response, refresh_token, max_age=60 * 60 * 24 * 30)
       return response
        
    else:
       return {"message": "Invalid password"}, 401
    
   except Exception as e:
       return {"message": "An error occured", 'error': str(e)}, 500
   


@app.route('/api/change/password', methods=['POST'])
@jwt_required()
def post():

   identity = get_jwt_identity()
   data = request.get_json()
   new_password = data['new_password']
   old_password = data['old_password']

   api = UserApi()
   user_data = api.get_by_username(identity)

   if user_data and check_password_hash(user_data.password, old_password):

      user_data.password = generate_password_hash(new_password)
      db.session.commit()
      
      response = make_response(jsonify({'message': 'Password updated !'}))
      return response
   
   else:
      response = make_response(jsonify({'Error': "Your password is incorrect"})), 404
      return response


### MAIN APP

if __name__ == "__main__":

  app.run(debug=True)




