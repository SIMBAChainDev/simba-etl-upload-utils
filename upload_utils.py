import json
import os
from datetime import datetime, timedelta
import requests
import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))


def token_expired(token_data: dict, offset: int = 60):
    """
    Checks to see if a token has expired, by checking the 'expires' key
    Adds an offset to allow for delays when performing auth processes

    :param token_data: the data dict to check for expiry. Should contain an 'expires' key
    :param offset: To allow for delays in auth processes,
    this number of seconds is added to the expiry time
    :return:
    """
    if 'expires' in token_data:
        expires = token_data['expires']
        now_w_offset = datetime.now() + timedelta(seconds=offset)
        expiry = datetime.fromtimestamp(expires)
        if now_w_offset >= expiry:
            log.info('Saved token expires within 60 seconds')
            return True
        log.info('Saved token valid for at least 60 seconds')
        return False
    else:
        log.info('No expiry date stored for token, assume expired')
        return True


def save_token(client_id: str, token_data: dict):
    """
    Saves the token data to a file.

    Checks the TOKEN_DIR environment variable for alternative token storage locations,
    otherwise uses the current working path

    Creates the token directory if it doesn't already exist.

    Adds an "expires" key to the auth token data, set to time "now" added to the expires_in time
    This is used later to discover if the token has expired

    Token files are named <client_id>_token.json

    :param client_id: The ID for the client, token files are named <client_id>_token.json
    :param token_data: The tokeauth data to save
    :return:
    """
    token_dir = os.getenv('TOKEN_DIR', './')
    os.makedirs(token_dir, exist_ok=True)
    token_file = os.path.join(token_dir, '{}_token.json'.format(client_id))
    with open(token_file, 'w') as t1:
        expiry_date = datetime.now() + timedelta(seconds=int(token_data['expires_in']))
        token_data['expires'] = int(expiry_date.timestamp())
        json.dump(token_data, t1)
        log.info('Saved token : {}'.format(token_file))


def get_saved_token(client_id: str):
    """
    Checks a local directory for a file containing an auth token
    If present, check the token hasn't expired, otherwise return it

    Raises exceptions if the token directory is missing,
    or if there is no token file,
    or if the token has expired, see def token_expired(token_data)

    Checks the TOKEN_DIR environment variable for alternative token storage locations,
    otherwise uses the current working path

    Token files are named <client_id>_token.json

    :param client_id: The ID for the client, token files are named <client_id>_token.json
    :return: a dict of the token data, retrieved from the token file.
    """
    token_dir = os.getenv('TOKEN_DIR', './')
    if os.path.isdir(token_dir):
        token_file = os.path.join(token_dir, '{}_token.json'.format(client_id))
        if os.path.isfile(token_file):
            with open(token_file, 'r') as t1:
                token_data = json.load(t1)
                log.info('Found saved token : {}'.format(token_file))

                if token_expired(token_data):
                    raise Exception('Token expiry date elapsed')
                return token_data
        raise Exception('Token file not found')
    raise Exception('Token dir not found')


def get_token_header():
    """
    Get an auth token from simbachain auth0
    Uses two environment variables, raises exception if not present

    :return: a dict to be used as a request header, of the form
        {
            'Authorization': 'Bearer aabbccdd....'
        }
    """

    client_id = os.getenv('CLIENT_ID')
    client_secret = os.getenv('CLIENT_SECRET')
    if client_id is None or client_secret is None:
        raise Exception('Must set CLIENT_ID and CLIENT_SECRET environment variables')
    try:
        # Try to use a saved token to avoid unnecessary auth processes
        token = get_saved_token(client_id)
        return {
            'Authorization': 'Bearer {}'.format(token['access_token'])
        }
    except Exception as e1:
        log.info(e1)

    # If the above failed, perform new auth process
    url = "https://simbachain-dev.auth0.com/oauth/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": "https://etl-upload.dev.simbachain.com/",
        "grant_type": "client_credentials"
    }

    resp = requests.post(url, json=payload)
    if resp.status_code != 200:
        raise Exception(resp.text)
    else:
        res = resp.json()
        access_token = res['access_token']
        # Save the token for reuse
        save_token(client_id, res)
        return {
            'Authorization': 'Bearer {}'.format(access_token)
        }


def whoami():
    """
    Performs auth and logs a dict of user data

    :return:
    :raises: Exception if GET returns an error status code and {'detail': 'Unauthorized'}
    """

    # HOST can be overridden with an environment variable, otherwise use the default
    url = os.getenv('SIMBA_UPLOAD_HOST', "https://etl-upload.dev.simbachain.com/whoami")

    # Perform auth process, return headers for future request calls
    headers = get_token_header()
    resp = requests.get(url, headers=headers)

    if resp.status_code != 200:
        log.error(resp.text)
    else:
        log.info(resp.json())
    resp.raise_for_status()


def post_file(filepath, name, mime_type='text/csv', project_uid='boeing'):
    """
    Upload a file to the SIMBA ETL server

    :param filepath: The path to the file to uplaod
    :param name: The name the file will be saved as
    :param mime_type: The type of file, default to 'text/csv'
    :param project_uid: The project to upload the file to. "boeing" is the default.
    :return:
    :raises: Exception if POST returns an error status code
    """
    url = "https://etl-upload.dev.simbachain.com"

    # The project to upload the data to
    data = {'project_uid': project_uid}
    headers = get_token_header()

    files = {
        'file': (name, open(os.path.join(filepath), 'rb'), mime_type, {})
    }
    resp = requests.post(
        '{}/file'.format(url),
        params=data,
        files=files,
        headers=headers
    )
    if resp.status_code != 200:
        log.error(resp.text)
    resp.raise_for_status()


if __name__ == '__main__':
    # Example usage of utility methods

    # Performs auth and logs a dict of user data
    whoami()

    # Posts an example file. Takes a file path and a name for that file to be stored as
    post_file('./data/company_dat.csv', 'company_dat.csv')