"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any
import base64
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """
       Client for GuardiCoreV2

       Args:
          username (str): The GuardiCore username for API access.
          password (bool): The GuardiCore password for API access.
    """

    def __init__(self, proxy: bool, verify: bool, base_url: str, username: str,
                 password: str):
        super().__init__(proxy=proxy, verify=verify, base_url=base_url)
        self.username = username
        self.password = password
        self.access_token = None
        self.base_url = base_url

        self.login()

    def login(self):
        integration_context = get_integration_context()

        if self.is_access_token_valid(integration_context):
            self.set_valid_token()
        else:
            self.generate_new_token()

    def is_access_token_valid(self, integration_context):
        integration_context = get_integration_context()
        access_token_expiration = integration_context.get('expires_in')
        access_token = integration_context.get('access_token')
        if access_token and access_token_expiration:
            access_token_expiration_datetime = datetime.strptime(
                access_token_expiration, DATE_FORMAT)
            return access_token_expiration_datetime > datetime.now()
        return False

    def generate_new_token(self):
        token = self.authenticate()
        # save token
        authorization_value = f'bearer {token}'
        self._headers = {
            "Authorization": authorization_value}  # change for all requests

    def save_jwt_token(self, token):
        expiration = get_jet_expiration(token)
        expiration_timestamp = datetime.now() + timedelta(seconds=expiration)
        context = {"access_token": self.access_token,
                   "expires_in": expiration_timestamp.strftime(DATE_FORMAT)}
        set_integration_context(context)
        demisto.debug(
            f"New access token that expires in : {expiration_timestamp.strftime(DATE_FORMAT)}"
            f" was set to integration_context.")

    def authenticate(self):
        body = {
            'username': self.username,
            'password': self.password
        }
        new_token = self._http_request(
            method='POST',
            url_suffix='/authenticate',
            json_data=body)

        if not new_token.get('access_token'):
            return_error(
                "GuardiCore error: The client credentials are invalid.")
        # save token
        new_token = new_token.get('access_token')
        self.save_jwt_token(new_token)
        return new_token

    def get_incident(self, url_params: str):
        data = self._http_request(
            method='GET',
            url_suffix=f'/incidents/{url_params}',
        )
        return data


''' HELPER FUNCTIONS '''


def get_jet_expiration(token):
    jwt_token = base64.b64decode(token.split(".")[1] + '==')
    jwt_token = json.loads(jwt_token)
    return jwt_token.get("exp")


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(
                e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_indicent(client: Client, args: Dict[str, Any]) -> CommandResults:
    id = args.get('id', None)
    if not id:
        raise ValueError('id not specified')

    # Call the Client function and get the raw response
    result = client.get_incident(id)

    return CommandResults(
        outputs_prefix='Guardicore.Incident',
        outputs_key_field='',  # TODO??
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    base_url = params.get('base_url')
    username = params.get('username')
    password = params.get('password')
    client = Client(username=username, password=password, base_url=base_url,
                    proxy="", verify=False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        args = demisto.args()
        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'guardicore-get-incident':
            return_results(get_indicent(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
