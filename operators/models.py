from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4

db_operator = SQLAlchemy()

def get_uuid():
    try:
        id = Operator.query.order_by(Operator.id.desc()).first()
        
        id = id.id
        if id:
            _id = int(id)
            _id = _id+1
            return _id
    except:
        return 1
    #return uuid4().hex

class Operator(db_operator.Model):
    __tablename__ = "operator"
    id = db_operator.Column(db_operator.String(32), primary_key=True, unique=True, default=get_uuid)
    email = db_operator.Column(db_operator.String(345), unique=True)
    password = db_operator.Column(db_operator.Text, nullable=False)
    administrator = db_operator.Column(db_operator.Boolean, default=False, nullable=True)