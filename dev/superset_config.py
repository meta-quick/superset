# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is included in the final Docker image and SHOULD be overridden when
# deploying the image to prod. Settings configured here are intended for use in local
# development environments. Also note that superset_config_docker.py is imported
# as a final step as a means to override "defaults" configured here
#
import logging
import os

from flask_login import login_user, logout_user
from celery.schedules import crontab
from dotenv import load_dotenv
from flask_appbuilder.utils.base import get_safe_redirect
from flask import current_app, g, make_response, request, Response
from superset.tasks.utils import get_current_user
from flask_login import current_user

from superset import appbuilder

load_dotenv()

log = logging.getLogger(__name__)

#Configure CORS
APP_NAME = "数安仪表盘"
DEFAULT_SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SAMESITE = None
SESSION_COOKIE_SECURE = False 
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_PATH = "/"
ENABLE_PROXY_FIX = True
GUEST_TOKEN_HEADER_NAME = "Authorization";
GLOBAL_ASYNC_QUERIES_REGISTER_REQUEST_HANDLERS = True
# SUPERSET_WEBSERVER_DOMAINS=["192.168.11.214:30001","192.168.12.41:8087","192.168.11.155:80","192.168.11.155:8083"]
# SESSION_COOKIE_DOMAIN = '.mydomain.com'

# TALISMAN_ENABLED = False
# APPLICATION_ROOT = '/superset'
FEATURE_FLAGS =  {
  "EMBEDDED_SUPERSET": True,
}

STATIC_ASSETS_PREFIX = "/superset"
WTF_CSRF_ENABLED = False
ENABLE_CORS = True

HTTP_HEADERS = {
    #Allow CROS
    # 'Access-Control-Allow-Origin': '*',  # Allows requests from any origin
    # 'Access-Control-Allow-Methods': 'GET,DELETE,PUT, POST, OPTIONS',  # Allowed HTTP methods
    # 'Access-Control-Allow-Headers': 'Authorization, Content-Type',  # Allowed headers
    # 'Access-Control-Allow-Credentials': 'true',  # Allow credentials to be sent with requests
    # 'X-Frame-Options': 'ALLOWALL'
}


CORS_OPTIONS = {
    "origins": ["*","http://localhost"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "resources": ["*"],
    "allow_headers": ["*"],
    "supports_credentials": True,
}

#Configure Babel
BABEL_DEFAULT_LOCALE = "zh"
LANGUAGES = {
"zh": {"flag": "cn", "name": "简体中文"},
# "en": {"flag": "us", "name": "English"},
}

logger = logging.getLogger()

#Configure Security
SECRET_KEY = "+l5h99lLzi0sTT7sse89R4"
SQLALCHEMY_DATABASE_URI = 'mysql://root:root@192.168.11.214:30309/superset'


#Configuration for Casdoor
try:
    from flask import (
       request,
       redirect,
       url_for,
    )
    from flask_appbuilder.views import expose
    from casdoor import CasdoorSDK
    from flask_appbuilder.security.views import AuthRemoteUserView
    from superset.security import SupersetSecurityManager
    from flask_appbuilder.security.manager import AUTH_REMOTE_USER
    logger.info("Using CASDOOR for authentication")
except Exception as ex:
    raise ex

auth_config = {
    "endpoint": os.getenv("CASSDOOR_ENDPOINT"),
    "client_id": os.getenv("APPLICATION_CLIENTID"),
    "client_secret": os.getenv("APPLICATION_CLIENTSECRET"),
    "certificate": os.getenv("APPLICATION_CERTIFICATE").replace("\\n", "\n"),
    "org_name": os.getenv("APPLICATION_ORGNAME"),
    "application_name": os.getenv("APPLICATION_NAME"),
}

class CasdoorJwt(object):
    casdoor_sdk = None
    def __init__(self,auth_config):
        self.casdoor_sdk = CasdoorSDK(**auth_config)

    def parse(self):
        #check if user is already authenticated or a jwt token is presen
        token = request.args.get('token', default=None, type=str)
        if token == None:
            token = request.headers.get("Authorization")
        if token == None:
            token = request.cookies.get("Authorization",default=None,type=str)

        if token:
            #remove bearer from token if present
            if token.startswith("Bearer "):
                token = token.replace("Bearer ", "")
            elif token.startswith("Bearer%20"):
                token = token.replace("Bearer%20", "")
            elif token.startswith("Bearer"):
                token = token.replace("Bearer", "")
        
            user = self.casdoor_sdk.parse_jwt_token(token)
            return user
        return None
    
    def parseToken(self,token):
        return self.casdoor_sdk.parse_jwt_token(token)
    
    def get_oauth_token(self,code):
        return self.casdoor_sdk.get_oauth_token(code=code)


g_casdoor_sdk = CasdoorJwt(auth_config)


class MetaAuthView(AuthRemoteUserView):
    casdoor_sdk = CasdoorJwt(auth_config)

    @expose("/login/", methods=["OPTIONS", "GET", "POST"])
    def login(self):
        user = self.casdoor_sdk.parse()
        if user:
            _user = self.appbuilder.sm.auth_user_remote_user(user.get("name"))
            login_user(_user)
            next_url = request.args.get("next", "")
            return redirect(get_safe_redirect(next_url))

        authorizationEndpoint = f"{auth_config['endpoint']}/login/oauth/authorize"
        params = {
            "client_id": auth_config["client_id"],
            "redirect_uri": os.environ.get("APPLICATION_CALLBACK"),
            "response_type": "code",
            "scope": "read",
        }
        casdoorUrl = f"{authorizationEndpoint}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
        return redirect(casdoorUrl)

    @expose("/callback/")
    def callback(self):
        code = request.args.get("code")
        token = self.casdoor_sdk.get_oauth_token(code=code)
        access_token = token.get("access_token")
        user = self.casdoor_sdk.parseToken(access_token)
        if user:
            _user = self.appbuilder.sm.auth_user_remote_user(user.get("name"))
            login_user(_user)
            next_url = request.args.get("next", "")
            return redirect(get_safe_redirect(next_url))
        else:
            return redirect(url_for("login"))    




class MetaSecurityManager(SupersetSecurityManager):
    authremoteuserview = MetaAuthView
    casdoor_sdk = CasdoorJwt(auth_config)
    def __init__(self, appbuilder):
        super(MetaSecurityManager, self).__init__(appbuilder)
    
    def auth_user_oauth(self, userinfo):
        # Custom authentication logic for JWT
        user = self.casdoor_sdk.parse()
        if user:
            _user = self.auth_user_remote_user(user.get("name"))
            login_user(_user)
            return _user
        return None

    def authenticate(self, username=None, password=None):
        """
        Overriding this method to handle JWT authentication instead of form-based.
        """
        user = self.casdoor_sdk.parse()
        if user:
            _user = self.auth_user_remote_user(user.get("name"))
            login_user(_user)
            return (True, _user)
        return (False, None)

    def auth_user_remote_user(self, username):
        """
        REMOTE_USER user Authentication

        :param username: user's username for remote auth
        :type self: User model
        """
        user = self.find_user(username=username)

        # User does not exist, create one if auto user registration.
        if user is None and self.auth_user_registration:
            role = self.find_role(self.auth_user_registration_role)
            if username == 'datasafe':
                role = self.appbuilder.sm.find_role('Admin')
            user = self.add_user(
                # All we have is REMOTE_USER, so we set
                # the other fields to blank.
                username=username,
                first_name=username,
                last_name="-",
                email=username + "@email.notfound",
                role=role,
            )

        # If user does not exist on the DB and not auto user registration,
        # or user is inactive, go away.
        elif user is None or (not user.is_active):
            return None

        self.update_user_auth_stat(user)
        return user
    
    @staticmethod
    def before_request():
        if current_user.is_authenticated:
            g.user = current_user
            return
        user = g_casdoor_sdk.parse()
        if user:
            _user = appbuilder.sm.auth_user_remote_user(user.get("name"))
            login_user(_user)
            g.user = _user
            return 
        g.user = current_user



CUSTOM_SECURITY_MANAGER = MetaSecurityManager
AUTH_TYPE = AUTH_REMOTE_USER
AUTH_ROLE_PUBLIC = 'Admin'
AUTH_USER_REGISTRATION = True