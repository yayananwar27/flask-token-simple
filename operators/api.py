from flask import Blueprint,Flask, request, jsonify, session
from flask_restful import Resource, Api
from flask_cors import CORS

#from flask_bcrypt import Bcrypt
#from config import ApplicationConfig
#from .models import db, User
#from flask_apispec.extension import FlaskApiSpec
from operators.operator import OperatorsAPI,LoginOperatorsAPI, LogoutOperatorsAPI, MeOperatorsAPI

operator_api = Blueprint('operator_api',__name__)
CORS(operator_api, supports_credentials=True, resources=r'/*', origins="*", allow_headers=["Content-Type", "Access-Control-Allow-Credentials","Access-Control-Allow-Origin"])

api = Api(operator_api)

api.add_resource(LoginOperatorsAPI, '/login')
api.add_resource(LogoutOperatorsAPI, '/logout')
api.add_resource(OperatorsAPI, '/')
api.add_resource(MeOperatorsAPI, '/@me')
