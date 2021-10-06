import base64
import hashlib
import random
import requests
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

    def _generate_pkce_code_verifier(length=43):
        """
        Taken from https://github.com/AzureAD/microsoft-authentication-library-for-python/blob/e94dda5f8140673e55e2cd825174ee98d886857e/msal/oauth2cli/oauth2.py#L276

        """
        assert 43 <= length <= 128
        verifier = "".join(  # https://tools.ietf.org/html/rfc7636#section-4.1
            random.sample(string.ascii_letters + string.digits + "-._~", length))
        code_challenge = (
            # https://tools.ietf.org/html/rfc7636#section-4.2
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"="))  # Required by https://tools.ietf.org/html/rfc7636#section-3
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
            params["code_challenge"] = self.pkce["code_challenge"],
            params["code_challenge_method"] = self.pkce["transformation"],
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
            data.update(
                {"code_verifier": self.pkce["code_verifier"]}
            )
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
        if self.access_token_method == "GET":
            params = data
            data = None
        # TODO: Proper exception handling
        resp = requests.request(
            self.access_token_method,
            url,
            params=params,
            data=data,
            headers=self.headers,
            auth=auth,
        )

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

