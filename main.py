from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
import facebook
#from pyfacebook import *
import wsgiref.handlers
import os
import sys
from datetime import datetime, timedelta
from hashlib import sha1
from hmac import new as hmac
from os.path import dirname, join as join_path
from random import getrandbits
from time import time
from urllib import urlencode, quote as urlquote
from uuid import uuid4

sys.path.insert(0, join_path(dirname(__file__), 'lib')) # extend sys.path

from django.utils import simplejson as json

from google.appengine.api.urlfetch import fetch as urlfetch, GET, POST
from google.appengine.ext import db
from google.appengine.ext.webapp import RequestHandler, WSGIApplication


OAUTH_APP_SETTINGS = {

    'twitter': {

        'consumer_key': 'add here key',
        'consumer_secret': 'add here secret',

        'request_token_url': 'https://twitter.com/oauth/request_token',
        'access_token_url': 'https://twitter.com/oauth/access_token',
        'user_auth_url': 'http://twitter.com/oauth/authorize',

        'default_api_prefix': 'http://twitter.com',
        'default_api_suffix': '.json',

        },

    'google': {

        'consumer_key': '',
        'consumer_secret': '',

        'request_token_url': 'https://www.google.com/accounts/OAuthGetRequestToken',
        'access_token_url': 'https://www.google.com/accounts/OAuthGetAccessToken',
        'user_auth_url': 'https://www.google.com/accounts/OAuthAuthorizeToken',

        },

    }

CLEANUP_BATCH_SIZE = 100
EXPIRATION_WINDOW = timedelta(seconds=60*60*1) # 1 hour

try:
    from config import OAUTH_APP_SETTINGS
except:
    pass

STATIC_OAUTH_TIMESTAMP = 12345 # a workaround for clock skew/network lag

# ------------------------------------------------------------------------------
# utility functions
# ------------------------------------------------------------------------------

def get_service_key(service, cache={}):
    if service in cache: return cache[service]
    return cache.setdefault(
        service, "%s&" % encode(OAUTH_APP_SETTINGS[service]['consumer_secret'])
        )

def create_uuid():
    return 'id-%s' % uuid4()

def encode(text):
    return urlquote(str(text), '')

def twitter_specifier_handler(client):
    return client.get('/account/verify_credentials')['screen_name']

OAUTH_APP_SETTINGS['twitter']['specifier_handler'] = twitter_specifier_handler

# ------------------------------------------------------------------------------
# db entities
# ------------------------------------------------------------------------------

class OAuthRequestToken(db.Model):
    """OAuth Request Token."""

    service = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class OAuthAccessToken(db.Model):
    """OAuth Access Token."""

    service = db.StringProperty()
    specifier = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

# ------------------------------------------------------------------------------
# oauth client
# ------------------------------------------------------------------------------

class OAuthClient(object):

    __public__ = ('callback', 'cleanup', 'login', 'logout')

    def __init__(self, service, handler, oauth_callback=None, **request_params):
        self.service = service
        self.service_info = OAUTH_APP_SETTINGS[service]
        self.service_key = None
        self.handler = handler
        self.request_params = request_params
        self.oauth_callback = oauth_callback
        self.token = None

    # public methods

    def get(self, api_method, http_method='GET', expected_status=(200,), **extra_params):

        if not (api_method.startswith('http://') or api_method.startswith('https://')):
            api_method = '%s%s%s' % (
                self.service_info['default_api_prefix'], api_method,
                self.service_info['default_api_suffix']
                )

        if self.token is None:
            self.token = OAuthAccessToken.get_by_key_name(self.get_cookie())

        fetch = urlfetch(self.get_signed_url(
            api_method, self.token, http_method, **extra_params
            ))

        if fetch.status_code not in expected_status:
            raise ValueError(
                "Error calling... Got return status: %i [%r]" %
                (fetch.status_code, fetch.content)
                )

        return json.loads(fetch.content)

    def post(self, api_method, http_method='POST', expected_status=(200,), **extra_params):

        if not (api_method.startswith('http://') or api_method.startswith('https://')):
            api_method = '%s%s%s' % (
                self.service_info['default_api_prefix'], api_method,
                self.service_info['default_api_suffix']
                )

        if self.token is None:
            self.token = OAuthAccessToken.get_by_key_name(self.get_cookie())

        fetch = urlfetch(url=api_method, payload=self.get_signed_body(
            api_method, self.token, http_method, **extra_params
            ), method=http_method)

        if fetch.status_code not in expected_status:
            raise ValueError(
                "Error calling... Got return status: %i [%r]" %
                (fetch.status_code, fetch.content)
                )

        return json.loads(fetch.content)

    def login(self):

        proxy_id = self.get_cookie()

        if proxy_id:
            return "FOO%rFF" % proxy_id
            self.expire_cookie()

        return self.get_request_token()

    def logout(self, return_to='/'):
        self.expire_cookie()
        self.handler.redirect(self.handler.request.get("return_to", return_to))

    # oauth workflow

    def get_request_token(self):

        token_info = self.get_data_from_signed_url(
            self.service_info['request_token_url'], **self.request_params
            )

        token = OAuthRequestToken(
            service=self.service,
            **dict(token.split('=') for token in token_info.split('&'))
            )

        token.put()

        if self.oauth_callback:
            oauth_callback = {'oauth_callback': self.oauth_callback}
        else:
            oauth_callback = {}

        self.handler.redirect(self.get_signed_url(
            self.service_info['user_auth_url'], token, **oauth_callback
            ))

    def callback(self, return_to='/'):

        oauth_token = self.handler.request.get("oauth_token")

        if not oauth_token:
            return get_request_token()

        oauth_token = OAuthRequestToken.all().filter(
            'oauth_token =', oauth_token).filter(
            'service =', self.service).fetch(1)[0]

        token_info = self.get_data_from_signed_url(
            self.service_info['access_token_url'], oauth_token
            )

        key_name = create_uuid()

        self.token = OAuthAccessToken(
            key_name=key_name, service=self.service,
            **dict(token.split('=') for token in token_info.split('&'))
            )

        if 'specifier_handler' in self.service_info:
            specifier = self.token.specifier = self.service_info['specifier_handler'](self)
            old = OAuthAccessToken.all().filter(
                'specifier =', specifier).filter(
                'service =', self.service)
            db.delete(old)

        self.token.put()
        self.set_cookie(key_name)
        self.handler.redirect(return_to)

    def cleanup(self):
        query = OAuthRequestToken.all().filter(
            'created <', datetime.now() - EXPIRATION_WINDOW
            )
        count = query.count(CLEANUP_BATCH_SIZE)
        db.delete(query.fetch(CLEANUP_BATCH_SIZE))
        return "Cleaned %i entries" % count

    # request marshalling

    def get_data_from_signed_url(self, __url, __token=None, __meth='GET', **extra_params):
        return urlfetch(self.get_signed_url(
            __url, __token, __meth, **extra_params
            )).content

    def get_signed_url(self, __url, __token=None, __meth='GET',**extra_params):
        return '%s?%s'%(__url, self.get_signed_body(__url, __token, __meth, **extra_params))

    def get_signed_body(self, __url, __token=None, __meth='GET',**extra_params):

        service_info = self.service_info

        kwargs = {
            'oauth_consumer_key': service_info['consumer_key'],
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_version': '1.0',
            'oauth_timestamp': int(time()),
            'oauth_nonce': getrandbits(64),
            }

        kwargs.update(extra_params)

        if self.service_key is None:
            self.service_key = get_service_key(self.service)

        if __token is not None:
            kwargs['oauth_token'] = __token.oauth_token
            key = self.service_key + encode(__token.oauth_token_secret)
        else:
            key = self.service_key

        message = '&'.join(map(encode, [
            __meth.upper(), __url, '&'.join(
                '%s=%s' % (encode(k), encode(kwargs[k])) for k in sorted(kwargs)
                )
            ]))

        kwargs['oauth_signature'] = hmac(
            key, message, sha1
            ).digest().encode('base64')[:-1]

        return urlencode(kwargs)

    # who stole the cookie from the cookie jar?

    def get_cookie(self):
        return self.handler.request.cookies.get(
            'oauth.%s' % self.service, ''
            )

    def set_cookie(self, value, path='/'):
        self.handler.response.headers.add_header(
            'Set-Cookie', 
            '%s=%s; path=%s; expires="Fri, 31-Dec-2021 23:59:59 GMT"' %
            ('oauth.%s' % self.service, value, path)
            )

    def expire_cookie(self, path='/'):
        self.handler.response.headers.add_header(
            'Set-Cookie', 
            '%s=; path=%s; expires="Fri, 31-Dec-1999 23:59:59 GMT"' %
            ('oauth.%s' % self.service, path)
            )


providers = {
    '<img src="http://www.google.com/friendconnect/scs/images/id_logo_google.jpg"/>'   : 'www.google.com/accounts/o8/id', # shorter alternative: "Gmail.com"
    '<img src="http://www.google.com/friendconnect/scs/images/id_logo_yahoo.jpg"/>'    : 'yahoo.com',
    '<img src="http://i138.photobucket.com/albums/q278/thegoldcobra/myspace.gif"/>'  : 'myspace.com',
    '<img src="http://1.bp.blogspot.com/_RwsFeSzQVLw/SdEwUE0RsUI/AAAAAAAAAUc/iEsUlWz3T5A/s320/id_logo_aim.gif"/>'      : 'aol.com',
    '<img src="http://aux.iconpedia.net/uploads/192014308200022101.png"/>OpenID' : 'myopenid.com'
    # add more here
}

class OAuthHandler(RequestHandler):

    def get(self, service, action=''):

        if service not in OAUTH_APP_SETTINGS:
            return self.response.out.write(
                "Unknown OAuth Service Provider: %r" % service
                )

        client = OAuthClient(service, self)

        if action in client.__public__:
            self.response.out.write(getattr(client, action)())
        else:
            self.response.out.write(client.login())
            
class MainHandler(webapp.RequestHandler):
    def post(self):
        self.get()
        
    def get(self):    
        self.API_KEY = 'add here key'# YOUR API KEY
        self.SECRET_KEY = 'add here secret'# YOUR SECRET KEY
        facebookapi = facebook.Facebook(self.API_KEY, self.SECRET_KEY)

        client = OAuthClient('twitter', self)
        gdata = OAuthClient('google', self, scope='http://www.google.com/calendar/feeds')      

        #first check twitter
        if not client.get_cookie():
            #after check facebook
            if not facebookapi.check_connect_session(self.request):
                user = users.get_current_user()
                #after check openID users
                if user:  # signed in already
                    logoutLink = '<a href="%s">sign out</a>' % (users.create_logout_url(self.request.uri))
                    template_vars = {}
                    template_vars['logout'] = logoutLink
                    template_vars['name'] = user.nickname()
                    self.tpl('main.html',template_vars)
                else:     # let user choose authenticator
                    links = ""
                    links = '<a href="/oauth/twitter/login"><img height="32px" src="https://si0.twimg.com/images/dev/buttons/sign-in-with-twitter-d.png"/></a>';
                    for name, uri in providers.items():
                        links = links + ('<a href="%s">%s</a> &nbsp;&nbsp;&nbsp;' % (
                            users.create_login_url(federated_identity=uri), name))     
                    template_vars = {}
                    template_vars['links'] = links
                    self.tpl('main.html',template_vars)        
              
                return
            else: #if signed in to facebook
                try:
                    user = facebookapi.users.getInfo( 
                    [facebookapi.uid], 
                    ['uid', 'name', 'birthday', 'relationship_status'])[0]

                    template_values = {
                        'name': user['name'],
                        'birthday': user['birthday'],
                        'relationship_status': user['relationship_status'],
                        'uid': user['uid'],
                        'logout' : '<a href="#" onclick="javascript:FB.Connect.logoutAndRedirect('+"'/'"+')">Logout</a>'
                        
                      }
                    self.tpl('main.html',template_values)
                except facebook.FacebookError:
                    template_values = {                
                        'error': "error"
                        }
                    self.tpl('main.html',template_values)
                    return
            
            return
        else: #if signed in to twitter
            info = client.get('/account/verify_credentials')
          
            template_values = {
                        'logout': '<a href="/oauth/twitter/logout">Logout from Twitter</a>',
                        'name': info['screen_name']                        
                      }
            self.tpl('main.html',template_values)
                    
                       
            return
            
        return 
        
                    
    def tpl(self, tpl_file, vars = {}):
        vars['apikey'] = self.API_KEY
        path = os.path.join(os.path.dirname(__file__), tpl_file)
        self.response.out.write(template.render(path, vars))
        
   
    

application = webapp.WSGIApplication([
    ('/oauth/(.*)/(.*)', OAuthHandler),
    ('/', MainHandler)
], debug=True)

def main():
    run_wsgi_app(application)

if __name__ == '__main__':
    main()
