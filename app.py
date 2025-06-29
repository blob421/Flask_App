from flask import Flask,  jsonify, request, make_response
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from urllib.parse import quote_plus
from sqlalchemy import  text
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import secrets
import datetime
import os


## Keys and config 

DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv("DB_PASS")
DB_SERVER = os.getenv('DB_SERVER')
DB_NAME = os.getenv('DB_NAME')

secure_key = secrets.token_hex(32)


params = {
    "server": DB_SERVER,
    "database": DB_NAME,
    "user": DB_USER,
    "password": DB_PASSWORD, 
    "driver": "ODBC Driver 18 for SQL Server"
}

connection_string = (
    f"DRIVER={{{params['driver']}}};"
    f"SERVER={params['server']},1433;"
    f"DATABASE={params['database']};"
    f"UID={params['user']};"
    f"PWD={params['password']};"
    f"Encrypt=yes;"
    f"TrustServerCertificate=no;"
)  

quoted = quote_plus(connection_string)
db_uri = f"mssql+pyodbc:///?odbc_connect={quoted}"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config["JWT_SECRET_KEY"] = f"{secure_key}"


db = SQLAlchemy(app)

### APP INIT

api = Api(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True)


exp = datetime.datetime.now() + datetime.timedelta(hours=1)
### DB INIT 

with app.app_context():

  users_exist = db.session.execute(text("""
      SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users'""")).first()

  if users_exist[0] == 0:  # Otherwise 1
          db.session.execute(text("""CREATE TABLE users (id INT PRIMARY KEY IDENTITY(1,1), 
                                     email VARCHAR(50), password VARCHAR(40) )"""))
          db.session.commit()
        


#  sessions_exist = db.session.execute(text("""
#      SELECT COUNT(*) FROM INFORMATION_SCHEMA"TABLES WHERE TABLE_NAME = 'sessions'""")).first()
  
#  if sessions_exist[0] == 0:
#     db.session.execute(text("""CREATE TABLE sessions (
#                             user_id INT PRIMARY KEY IDENTITY(1,1),
#                             FOREIGN KEY (user_id) REFERENCES users(id),
#                             token VARCHAR(100),
#                             )"""))
     
############################################
#Resources


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

def serialize_row(row):
    return {
        "date": row[0].isoformat(),
        "price": float(row[1]),
        "volume": float(row[2]),
        "market_cap": float(row[3]),
        "availablesupply": float(row[4]),
        "totalsupply": int(row[5]),
        "fullyDilutedValuation": float(row[6]),
        "priceChange1h": float(row[7]),
        "priceChange1d": float(row[8]),
        "priceChange1w": float(row[9])
        
        }
        
      

class Btc(Resource):
  
  def get(self):

    row = db.session.execute(text("SELECT * FROM bitcoin_data")).all()
    clean = [serialize_row(ro) for ro in row]
    return jsonify({"content": clean})
  

class Eth(Resource):
  
  def get(self):

    row = db.session.execute(text("SELECT * FROM eth_data")).all()
    return str(row)


@app.route('/api/sign-up', methods=['POST'])
def register():
  try:
    data = request.get_json()
    print(data)
    username = data['username']
    password = data['password']

    if not username or not password:
       return jsonify({"message": "Username and password required"}), 400
    
    
    
    stmt = text("INSERT INTO users (email, password) VALUES (:email, :password)")
    db.session.execute(stmt, {"email": username, "password": password})
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
    
    if query.password == password:
        id = query.id
        access_token = create_access_token(identity=username, expires_delta=datetime.timedelta(minutes=60))
        """ session = secrets.token_hex(32)

        delete_session= db.session.query(Session).filter_by(user_id = user['id']).first()
        if delete_session:
            db.session.delete(delete_session)
            db.session.commit()
            make_session = Session(user_id=user['id'], session_id=session, expires_at=exp)
            db.session.add(make_session)
            db.session.commit()
        else:
            make_session = Session(user_id=user['id'], session_id=session, expires_at=exp)
            db.session.add(make_session)
            db.session.commit()"""
        
  
        response = make_response(jsonify({"message": "Login successful!", "access_token": access_token, "user_id": id})) #"session_id": session}))
        #response.set_cookie("Jwttoken", access_token, SameSite=None, Secure=False, httponly=True, max_age=100000000)
      
        return response
        
        
   
    else:
       return {"message": "Invalid password"}, 401
    
   except Exception as e:
       return {"message": "An error occured", 'error': str(e)}, 500
   

api.add_resource(User_data, '/api/users/<int:id>')
api.add_resource(Btc, '/api/bitcoin')
api.add_resource(Eth, '/api/eth')
#api.add_resource(Book, '/api/books/<int:book_id>')

### PROGRAM ##################

if __name__ == "__main__":

  app.run(debug=False)




