import base64
import hashlib
import json
import logging
import requests
import secrets
import string
from urllib.parse import parse_qsl

from django.utils.http import urlencode

from allauth.socialaccount.providers.oauth2.client import (
    OAuth2Client,
    OAuth2Error,
)


class MicrosoftOAuth2Client(OAuth2Client):
    """
    Custom client because of PKCE:
        * requires `code_verifier` and `scope` field in token_url
        * requires `code_challenge`, `transformation` field in redirect_url
    """
    def __init__(
        self,
        *args, **kwargs
    ):
        self.pkce = self._generate_pkce_code_verifier(43)
        super(MicrosoftOAuth2Client, self).__init__(*args, **kwargs)

    def _generate_pkce_code_verifier(self, length=43):
        """
        Taken from https://github.com/AzureAD/microsoft-authentication-library-for-python/blob/e94dda5f8140673e55e2cd825174ee98d886857e/msal/oauth2cli/oauth2.py#L276

        """
        assert 43 <= length <= 128
        # verifier
        verifier = secrets.token_urlsafe(96)[:length]

        #code_challenge
        hashed = hashlib.sha256(verifier.encode('ascii')).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode('ascii')[:-1]

        # print verifier here
        logging.info("verifier at the _generate_pkce_code_verifier: " + verifier)
        return {
            "code_verifier": verifier,
            "transformation": "S256",  # In Python, sha256 is always available
            "code_challenge": code_challenge,
        }


    def get_redirect_url(self, authorization_url, extra_params):
        params = {
            "client_id": self.consumer_key,
            "response_type": "code",
            "redirect_uri": self.callback_url,
            "response_mode": "query",
            "scope": self.scope,
        }
        if self.pkce:
            params["code_challenge"] = self.pkce["code_challenge"]
            params["code_challenge_method"] = self.pkce["transformation"]
        if self.state:
            params["state"] = self.state
        params.update(extra_params)
        return "%s?%s" % (authorization_url, urlencode(params))

    def get_access_token(self, code):
        data = {
            "redirect_uri": self.callback_url,
            "grant_type": "authorization_code",
            "code": code,
            "scope": self.scope,
        }
        if self.pkce:
            data["code_verifier"] = self.pkce["code_verifier"]
        if self.basic_auth:
            auth = requests.auth.HTTPBasicAuth(self.consumer_key, self.consumer_secret)
        else:
            auth = None
            data.update(
                {
                    "client_id": self.consumer_key,
                    "client_secret": self.consumer_secret,
                }
            )
        params = None
        self._strip_empty_keys(data)
        url = self.access_token_url

        self.access_token_method = "POST"

        # print verifier here again so we can see

        logging.info("data just before POST")
        logging.info(json.dumps(data))
        logging.info("url just before POST: " + url)

        # TODO: Proper exception handling
        resp = requests.request(
            self.access_token_method,
            url,
            params=params,
            data=data,
            headers=self.headers,
            auth=auth,
        )

        logging.info(" just after POST ")

        access_token = None
        if resp.status_code in [200, 201]:
            # Weibo sends json via 'text/plain;charset=UTF-8'
            if (
                resp.headers["content-type"].split(";")[0] == "application/json"
                or resp.text[:2] == '{"'
            ):
                access_token = resp.json()
            else:
                access_token = dict(parse_qsl(resp.text))
        if not access_token or "access_token" not in access_token:
            raise OAuth2Error("Error retrieving access token: %s" % resp.content)
        return access_token

