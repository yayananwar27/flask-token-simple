#from dotenv import load_dotenv
#import os

#load_dotenv()
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
import redis

class redis_conn:
    def __init__(self):
        self.key = ''
        self.r = redis.from_url("redis://<IP SERVER REDIS>:6379")
        self.value = ''
        
    def get(self, key):
        data = self.r.get(key)
        return data

    def set(self, key, value):
        data = self.r.set(key, value)
        return data

    def delete(self, key):
        data = self.r.delete(key)
        return data


class ApplicationConfig:
    #SECRET_KEY = os.environ["SECRET_KEY"]
    SECRET_KEY = "<YOUR SECRET KEY>"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = r"sqlite:///hotspot.sqlite"

    #SESSION_TYPE = "redis"
    #SESSION_PERMANENT = False
    #SESSION_USE_SIGNER = True
    #SESSION_REDIS = redis.from_url("redis://<IP redis server:PORT")

    APISPEC_SPEC = APISpec(
        title='Hotspot Jakwifi Project',
        version='1.0.0',
        plugins=[MarshmallowPlugin()],
        openapi_version='2.0.0'
    )
    APISPEC_SWAGGER_URL = "/swagger/"  # URI to access API Doc JSON
    APISPEC_SWAGGER_UI_URL = '/swagger-ui/'  # URI to access UI of API Doc
