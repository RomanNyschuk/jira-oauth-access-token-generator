#!/usr/bin/env python
# Originally Lifted from http://bit.ly/1qpxJlj back in 2016.

from oauthlib.oauth1 import SIGNATURE_RSA
from requests_oauthlib import OAuth1Session


def read(file_path):
    """ Read a file and return it's contents. """
    with open(file_path) as f:
        return f.read()

#Replace Consumer Key, RSA Key Path, and your Jira URL!

# The Consumer Key created while setting up the "Incoming Authentication" in
# JIRA for the Application Link.
CONSUMER_KEY = u'0dab23cd64d14529894a470da541306f'

# The contents of the rsa.pem file generated (the private RSA key)
RSA_KEY = read('/opt/stackstorm/packs/jira/jira.pem')

# The URLs for the JIRA instance
JIRA_SERVER = 'http://jira-7-dev:8080'
REQUEST_TOKEN_URL = JIRA_SERVER + '/plugins/servlet/oauth/request-token'
AUTHORIZE_URL = JIRA_SERVER + '/plugins/servlet/oauth/authorize'
ACCESS_TOKEN_URL = JIRA_SERVER + '/plugins/servlet/oauth/access-token'

#Print what we think your JIRA server should be (What you gave us above):
print("\nJIRA SERVER: " + JIRA_SERVER + "")
print("CONSUMER_KEY: " + CONSUMER_KEY + "")

# Step 1: Get a request token
oauth = OAuth1Session(CONSUMER_KEY, signature_type='auth_header',
                      signature_method=SIGNATURE_RSA, rsa_key=RSA_KEY)
request_token = oauth.fetch_request_token(REQUEST_TOKEN_URL)

print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\nSTEP 1: GET THE REQUEST TOKENS:")
tokens=request_token
token=tokens['oauth_token']
secret=tokens['oauth_token_secret']
print("Token: " + token)
print("Secret: " + secret + "\n\n")

# Step 2: Get the end-user to provide JIRA authorization
print("STEP2: AUTHORIZE FROM JIRA")
print("Visit to the following URL to provide authorization:")
print(AUTHORIZE_URL + "?oauth_token=" + token)
print("\n^^Copy the above URL, visit it, and hit 'accept' on the prompt that follows.^^\n")
while input("Press any key to continue ONLY AFTER authorizing your token...!"):
    pass

# XXX: This is an ugly hack to get around the verfication string
# that the server needs to supply as part of authorization response.
# But we hard code it.
oauth._client.client.verifier = u'verified'
access_token = oauth.fetch_access_token(ACCESS_TOKEN_URL)
print(access_token)
print("\n")

# You should now be able to use your access token with JIRA ... Hooray!
