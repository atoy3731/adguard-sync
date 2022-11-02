import requests
import os
import json
import time
from exceptions import UnauthenticatedError, SystemError

REQUEST_HEADERS = {'Content-Type': 'application/json'}

def get_response(url, cookie):
    """
    Helper function to handle errors and keep it DRY
    """
    cookies = {
        'agh_session': cookie
    }

    response = requests.get(url, cookies=cookies)

    if response.status_code == 403:
        raise UnauthenticatedError
    elif response.status_code != 200:
        raise SystemError
    
    return json.loads(response.text)


def update_settings(setting, primary_settings, secondary_settings, url, cookie):
    """
    Update main DNS settings on secondary AdGuard if necessary
    :param setting: Name of the setting to change.
    :param primary_settings: Primary settings for primary AdGuard.
    :param secondary_settings: Secondary settings for secondary AdGuard.
    :param url: Base URL for updating settings.
    :param cookie: Auth cookie.
    """
    cookies = {
        'agh_session': cookie
    }

    if primary_settings != secondary_settings:
        print("  - Updating {} settings".format(setting))
        response = requests.post(url, cookies=cookies, data=json.dumps(primary_settings), headers=REQUEST_HEADERS)

        if response.status_code == 403:
            raise UnauthenticatedError
        elif response.status_code != 200:
            raise SystemError