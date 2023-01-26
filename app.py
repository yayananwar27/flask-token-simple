from flask import Flask, request, jsonify, session
from config import ApplicationConfig
from flask_apispec.extension import FlaskApiSpec
#from flask_session import Session

from operators.api import operator_api
from operators.operator import OperatorsAPI, LoginOperatorsAPI, LogoutOperatorsAPI, MeOperatorsAPI
from operators.models import db_operator

app = Flask(__name__)
app.config.from_object(ApplicationConfig)

#server_session = Session(app)

db_operator.init_app(app)

with app.app_context():
    db_operator.create_all()


docs = FlaskApiSpec(app)

app.register_blueprint(operator_api, url_prefix='/operator')

docs.register(OperatorsAPI, blueprint='operator_api')
docs.register(LoginOperatorsAPI, blueprint='operator_api')
docs.register(LogoutOperatorsAPI, blueprint='operator_api')
docs.register(MeOperatorsAPI, blueprint='operator_api')


if __name__ == "__main__":
    app.run('0.0.0.0', port=8088,debug=True)