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
from flask_caching.backends.filesystemcache import FileSystemCache
from dotenv import load_dotenv
from flask_appbuilder.utils.base import get_safe_redirect

load_dotenv()

logger = logging.getLogger(__name__)

BABEL_DEFAULT_LOCALE = "zh"
 
LANGUAGES = {
"zh": {"flag": "cn", "name": "简体中文"},
# "en": {"flag": "us", "name": "English"},
}

logger = logging.getLogger()
SECRET_KEY = "jgBy0p7IjccxAOYG4Fh6QCCRzPikQ00Fv8+l5h99lLzi0sTT7sse89R4"
SQLALCHEMY_DATABASE_URI = 'mysql://root:root@192.168.11.214:30309/superset'


#Configuration for Casdoor
try:
    from flask import (
       request,
       redirect,
       url_for,
       session,
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

class MetaAuthView(AuthRemoteUserView):
    casdoor_sdk = CasdoorSDK(**auth_config)

    @expose("/login/", methods=["GET", "POST"])
    def login(self):
        #check if user is already authenticated or a jwt token is present
        token = request.headers.get("Authorization")
        if token:
            #remove bearer from token if present
            if token.startswith("Bearer "):
                token = token.replace("Bearer ", "")
            elif token.startswith("Bearer%20"):
                token = token.replace("Bearer%20", "")
            elif token.startswith("Bearer"):
                token = token.replace("Bearer", "")
         
            user = self.casdoor_sdk.parse_jwt_token(token)
            if user:
                _user = self.appbuilder.sm.auth_user_remote_user(user.get("name"))
                login_user(_user)
                next_url = request.args.get("next", "")
                return redirect(get_safe_redirect(next_url))

        authorizationEndpoint = f"{auth_config['endpoint']}/login/oauth/authorize"
        params = {
            "client_id": auth_config["client_id"],
            "redirect_uri": "http://192.168.11.155:8083/callback",
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
        user = self.casdoor_sdk.parse_jwt_token(access_token)
        if user:
            _user = self.appbuilder.sm.auth_user_remote_user(user.get("name"))
            login_user(_user)
            next_url = request.args.get("next", "")
            return redirect(get_safe_redirect(next_url))
        else:
            return redirect(url_for("login"))   
            

class MetaSecurityManager(SupersetSecurityManager):
    authremoteuserview = MetaAuthView
    def __init__(self, appbuilder):
        super(MetaSecurityManager, self).__init__(appbuilder)
    
    @property
    def auth_remote_user_env_var(self) -> str:
        return self.appbuilder.get_app.config["AUTH_REMOTE_USER_ENV_VAR"]
    

CUSTOM_SECURITY_MANAGER = MetaSecurityManager
AUTH_TYPE = AUTH_REMOTE_USER
AUTH_ROLE_PUBLIC = 'Admin'
AUTH_USER_REGISTRATION = True