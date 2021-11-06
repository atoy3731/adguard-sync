import requests
import os
import json
import time
import entries
import blocked_services
import block_white_lists
import custom_rules
from exceptions import UnauthenticatedError

ADGUARD_PRIMARY = os.environ['ADGUARD_PRIMARY']
ADGUARD_SECONDARY = os.environ['ADGUARD_SECONDARY']

ADGUARD_USER = os.environ['ADGUARD_USER']
ADGUARD_PASS = os.environ['ADGUARD_PASS']

# Optional, use if your secondary AdGuard has different credentials
SECONDARY_ADGUARD_USER = os.environ.get('SECONDARY_ADGUARD_USER', ADGUARD_USER)
SECONDARY_ADGUARD_PASS = os.environ.get('SECONDARY_ADGUARD_PASS', ADGUARD_PASS)

# By default, sync all
SYNC_ENTRIES = os.environ.get('SYNC_ENTRIES', 'true').lower() == 'true'
SYNC_BLOCKED_SERVICES = os.environ.get('SYNC_BLOCKED_SERVICES', 'true').lower() == 'true'
SYNC_BLOCK_WHITE_LISTS = os.environ.get('SYNC_BLOCK_WHITE_LISTS', 'true').lower() == 'true'
SYNC_CUSTOM_RULES = os.environ.get('SYNC_CUSTOM_RULES', 'true').lower() == 'true'

REFRESH_INTERVAL_SECS = int(os.environ.get('REFRESH_INTERVAL_SECS', '60'))


def get_login_cookie(url, user, passwd):
    """
    Logs into AdGuard URL using username/password and returns a valid session cookie.
    :param url: Base URL of AdGuard
    :param user: Username of AdGuard
    :param passwd: Password of AdGuard
    :return: Session token
    """

    creds = {
        'name': user,
        'password': passwd
    }

    response = requests.post('{}/control/login'.format(url), data=json.dumps(creds))

    if response.status_code != 200:
        print('ERROR: Unable to acquire cookie.')
        print('Message: {}'.format(response.text))
        return None

    return response.cookies['agh_session']


if __name__ == '__main__':
    print("Running Adguard Sync for '{}' => '{}'..".format(ADGUARD_PRIMARY, ADGUARD_SECONDARY))

    # Get initial login cookie
    primary_cookie = get_login_cookie(ADGUARD_PRIMARY, ADGUARD_USER, ADGUARD_PASS)
    secondary_cookie = get_login_cookie(ADGUARD_SECONDARY, SECONDARY_ADGUARD_USER, SECONDARY_ADGUARD_PASS)

    if primary_cookie is None or secondary_cookie is None:
        exit(1)

    while True:
        try:
            # Reconcile entries
            if SYNC_ENTRIES:
                entries.reconcile(ADGUARD_PRIMARY, ADGUARD_SECONDARY, primary_cookie, secondary_cookie)

            # Reconcile blocked services
            if SYNC_BLOCKED_SERVICES:
                blocked_services.reconcile(ADGUARD_PRIMARY, ADGUARD_SECONDARY, primary_cookie, secondary_cookie)

            # Reconcile block/white lists
            if SYNC_BLOCK_WHITE_LISTS:
                block_white_lists.reconcile(ADGUARD_PRIMARY, ADGUARD_SECONDARY, primary_cookie, secondary_cookie)

            # Reconcile custom rules
            if SYNC_CUSTOM_RULES:
                custom_rules.reconcile(ADGUARD_PRIMARY, ADGUARD_SECONDARY, primary_cookie, secondary_cookie)

        except UnauthenticatedError:
            primary_cookie = get_login_cookie(ADGUARD_PRIMARY, ADGUARD_USER, ADGUARD_PASS)
            secondary_cookie = get_login_cookie(ADGUARD_SECONDARY, SECONDARY_ADGUARD_USER, SECONDARY_ADGUARD_PASS)

            if primary_cookie is None or secondary_cookie is None:
                exit(1)

        time.sleep(REFRESH_INTERVAL_SECS)
