from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class QueryMeta(type):
    def __new__(cls, name, bases, dict):
        if 'model' in dict:
            model = dict['model']
        
            def get_by_username(self, identity):
                user_data = db.session.query(model).filter_by(username = identity).first()
                return user_data
            
            def get_all(self):
                all_data = db.session.query(model).order_by(model.date.desc()).limit(3000)

                return all_data[::30]
                
            dict['get_by_username'] = get_by_username
            dict['get_all'] = get_all

        return super().__new__(cls, name, bases, dict)
    

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)


class Bitcoin_data(db.Model):
    date = db.Column(db.DateTime(timezone=True), primary_key=True, index=True) 
    price = db.Column(db.Numeric(20,2)) 
    volume = db.Column(db.Numeric(20,2)) 
    marketcap = db.Column(db.Numeric(20,2)) 
    availablesupply = db.Column(db.Numeric(20,2)) 
    totalsupply = db.Column(db.Integer) 
    fullydilutedvaluation = db.Column(db.Numeric(20,2)) 
    pricechange1h = db.Column(db.Numeric(20,2)) 
    pricechange1d = db.Column(db.Numeric(20,2)) 
    pricechange1w = db.Column(db.Numeric(20,2))

    def serialize(self):
     
     return {
        "date": self.date.isoformat() if self.date else None,
        "price": float(self.price) if self.price else None,
    }


class Eth_data(db.Model):
    date = db.Column(db.DateTime(timezone=True), primary_key=True, index=True) 
    price = db.Column(db.Numeric(20,2)) 
    volume = db.Column(db.Numeric(20,2)) 
    marketcap = db.Column(db.Numeric(20,2)) 
    availablesupply = db.Column(db.Numeric(20,2)) 
    totalsupply = db.Column(db.Integer) 
    fullydilutedvaluation = db.Column(db.Numeric(20,2)) 
    pricechange1h = db.Column(db.Numeric(20,2)) 
    pricechange1d = db.Column(db.Numeric(20,2)) 
    pricechange1w = db.Column(db.Numeric(20,2))


class Market_data(db.Model):
    date = db.Column(db.DateTime(timezone=True), primary_key=True, index=True) 
    volume = db.Column(db.BigInteger) 
    marketcap = db.Column(db.BigInteger) 
    btcdominance = db.Column(db.Numeric(20,2))
    marketcapchange = db.Column(db.Numeric(20,2))
    volumechange = db.Column(db.Numeric(20,2))
    btcdominancechange = db.Column(db.Numeric(20,2))
    fear_greed_value = db.Column(db.Integer)
    fear_greed_name = db.Column(db.String(20))


class UserApi(metaclass=QueryMeta):
    model = Users

class CryptoApi(metaclass=QueryMeta):
    model = Bitcoin_data

