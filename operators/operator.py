from flask import jsonify, request, make_response, current_app#, session
from flask_restful import Resource
from marshmallow import Schema, fields
from flask_apispec.views import MethodResource
from flask_apispec import marshal_with, doc, use_kwargs
from flask_cors import CORS, cross_origin
from functools import wraps
from authlib.jose import jwt, JoseError

from config import redis_conn
from werkzeug.security import generate_password_hash, check_password_hash
from .models import db_operator, Operator

import json
import ast

redcon = redis_conn()

#def add_headers(f):
#    @wraps(f)
#    def decorated_function(*args, **kwargs):
#        resp = make_response(f(*args, **kwargs))
#        resp.headers['Access-Control-Allow-Credentials'] = 'true'
#        return resp
#    return decorated_function

def check_header(f):
    @wraps(f)
    def check_authorization(*args,**kwargs):
        try:
            authorization = request.headers['Authorization']
            redcon.get(authorization).decode('utf-8')
            if redcon == None:
                return jsonify({"message": "Unauthorized"}), 401
        except:
            return jsonify({"message": "Unauthorized"}), 401
        resp = make_response(f(*args, **kwargs))
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        return resp
    return check_authorization
        
def get_token(payload):
    header = {'alg': 'HS256'}
    return jwt.encode(
        header, payload, current_app.config['SECRET_KEY']
    ).decode()

class OperatorSchemaLogin(Schema):
    email = fields.String(required=True, metadata={"description":"E-mail untuk Username"})
    password = fields.String(required=True, metadata={"description":"password Username"})

class OperatorSchemaLogout(Schema):
    token = fields.String(required=True, metadata={"description":"Token to Delete"})

class OperatorsSchema(Schema):
    id = fields.String(required=True, metadata={"description":"Unique ID Username"})
    email = fields.String(required=True, metadata={"description":"E-mail untuk Username"})
    administrator = fields.Boolean(metadata={"description":"administrator access True/False"})

class OperatorSchemaCreate(Schema):
    email = fields.String(required=True, metadata={"description":"E-mail untuk Username"})
    password = fields.String(required=True, metadata={"description":"password Username"})
    administrator = fields.Boolean(metadata={"description":"administrator access True/False"})

class OperatorSchemaUpdate(Schema):
    id = fields.String(required=True, metadata={"description":"Unique ID Username"})
    email = fields.String(metadata={"description":"E-mail untuk Username"})
    password = fields.String(metadata={"description":"password Username"})
    administrator = fields.Boolean(metadata={"description":"administrator access True/False"})

class OperatorSchemaDelete(Schema):
    id = fields.String(required=True, metadata={"description":"Unique ID Username"})

class OperatorsSchemaList(Schema):
    response = fields.List(fields.Nested(OperatorsSchema))

class LoginOperatorsAPI(MethodResource, Resource):
    @doc(description='Login Operator', tags=['Operator Func'])
    @use_kwargs(OperatorSchemaLogin, location=('json'))
    @marshal_with(OperatorsSchema)  # marshalling
    #@cross_origin()
    #@add_headers
    def post(self, **kwargs):
        try:
            email = kwargs['email']
            password = kwargs['password']

            operator_exists = Operator.query.filter_by(email=email).first()

            if operator_exists is None:
                return jsonify({"message": "Unauthorized"}), 401

            if not check_password_hash(operator_exists.password, password):
                return jsonify({"message": "Unauthorized"}), 401
            
            #session['user_id'] = operator_exists.id
            #session['username'] = operator_exists.email
            
            payload = {'user_id' : operator_exists.id}
            token = get_token(payload)
            
            data = {
                "id": operator_exists.id,
                "email": operator_exists.email,
                "administrator":operator_exists.administrator
            }

            redcon.set(token,str(data))
            
            data['token'] = token
            return jsonify(data)

        except Exception as e:
            print(e)
            error = {"message":e}
            respone = jsonify(error)
            respone.status_code = 500
            return respone

class LogoutOperatorsAPI(MethodResource, Resource):
    @doc(description='Logout Operator', tags=['Operator Func'], params={'Authorization': {'in': 'header', 'description': 'An authorization token'}})
    @use_kwargs(OperatorSchemaLogout, location=('json'))
    @marshal_with(OperatorsSchema)  # marshalling
    @check_header
    def post(self, **kwargs):
        try:
            #session.pop("user_id")
            #session.pop("username")
            token = kwargs['token']
            redcon.delete(token)
            return "200"

        except Exception as e:
            print(e)
            error = {"message":e}
            respone = jsonify(error)
            respone.status_code = 500
            return respone

class MeOperatorsAPI(MethodResource, Resource):
    @doc(description='Me Operator', tags=['Operator Func'], params={'Authorization': {'in': 'header', 'description': 'An authorization token'}})
    @marshal_with(OperatorsSchema)  # marshalling
    @check_header
    def get(self):
        token = request.headers['Authorization']
        data = redcon.get(token).decode("utf-8")
        result = ast.literal_eval(data)
        return jsonify(result)

class OperatorsAPI(MethodResource, Resource):
    @doc(description='Create Operator', tags=['Operator'])
    @use_kwargs(OperatorSchemaCreate, location=('json'))
    @marshal_with(OperatorsSchema)  # marshalling
    #@check_header
    def post(self, **kwargs):
        try:
            #user_id = session.get("user_id")
            #username = session.get("username")
        
            #if not user_id:
            #    return jsonify({"error": "Unauthorized"}), 401

            #if not username:
            #    return jsonify({"error": "Unauthorized"}), 401
            
            email = kwargs['email']
            password = kwargs['password']
            administrator = False
            try:
                administrator = kwargs['administrator']
            except:
                administrator = False

            operator_exists = Operator.query.filter_by(email=email).first() is not None

            if operator_exists:
                return jsonify({"message": "User already exists"}), 409

            hashed_password = generate_password_hash(password)
            new_operator = Operator(email=email, password=hashed_password, administrator=administrator)
            db_operator.session.add(new_operator)
            db_operator.session.commit()

            operator = Operator.query.filter_by(email=email).first()
            print(operator)

            return jsonify({
                "id": operator.id,
                "email": operator.email,
                "adminstrator": operator.administrator
            })

        except Exception as e:
            print(e)
            error = {"message":e}
            respone = jsonify(error)
            respone.status_code = 500
            return respone

    @doc(description='List Operator', tags=['Operator'], params={'Authorization': {'in': 'header', 'description': 'An authorization token'}})
    @marshal_with(OperatorsSchemaList)  # marshalling
    @check_header
    def get(self, **kwargs):
        #user_id = session.get("user_id")
        #username = session.get("username")
        
        #if not user_id:
        #    return jsonify({"error": "Unauthorized"}), 401

        #if not username:
        #    return jsonify({"error": "Unauthorized"}), 401

        operators = Operator.query.order_by(Operator.email.asc()).all()
        
        operators_list = []

        for operator in operators:
            _operator = {'id':operator.id, 'email':operator.email, 'administrator':operator.administrator}
            operators_list.append(_operator)

        return jsonify(operators_list)

    @doc(description='Update Operator', tags=['Operator'], params={'Authorization': {'in': 'header', 'description': 'An authorization token'}})
    @use_kwargs(OperatorSchemaUpdate, location=('json'))
    @marshal_with(OperatorsSchema)  # marshalling
    @check_header
    def put(self, **kwargs):
        #user_id = session.get("user_id")
        #username = session.get("username")
        
        #if not user_id:
        #    return jsonify({"error": "Unauthorized"}), 401

        #if not username:
        #    return jsonify({"error": "Unauthorized"}), 401
        
        id = kwargs['id']
        try:
            email = kwargs['email']
        except:
            email = None
        try : 
            password = kwargs['password']
        except:
            password = None
        try : 
            administrator = kwargs['administrator']
        except:
            administrator = None
 
        operator = Operator.query.filter_by(id=id).first()
        if operator:
            if email != None:
                operator.email = email
                db_operator.session.commit()
            if password != None:
                hashed_password = generate_password_hash(password)
                operator.password = hashed_password
                db_operator.session.commit()
            if administrator != None:
                operator.adminastrator = administrator
                db_operator.session.commit()

            operator = Operator.query.filter_by(id=id).first()
        
            return jsonify({
                "id": operator.id,
                "email": operator.email
             })
    
        return jsonify({"message": "User Not exists"}), 404
        
        
    @doc(description='Delete Operator', tags=['Operator'], params={'Authorization': {'in': 'header', 'description': 'An authorization token'}})
    @use_kwargs(OperatorSchemaDelete, location=('json'))
    @marshal_with(OperatorsSchema)  # marshalling
    @check_header
    def delete(self, **kwargs):
        #user_id = session.get("user_id")
        #username = session.get("username")
        
        #if not user_id:
        #    return jsonify({"error": "Unauthorized"}), 401

        #if not username:
        #    return jsonify({"error": "Unauthorized"}), 401
        
        id = kwargs['id']
        operator = Operator.query.filter_by(id=id).first()
        if operator:
            temp_id = operator.id
            temp_email = operator.email
            db_operator.session.delete(operator)
            db_operator.session.commit()
            
            return jsonify({
                "id": temp_id,
                "email": temp_email
             })

        return jsonify({"message": "User Not exists"}), 404