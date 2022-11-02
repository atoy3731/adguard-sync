import requests
import os
import json
import time
import entries
import blocked_services
import block_allow_lists
import custom_rules
from exceptions import UnauthenticatedError, SystemError
from settings import general, dns, encryption
import common

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
SYNC_BLOCK_ALLOW_LISTS = os.environ.get('SYNC_BLOCK_ALLOW_LISTS', 'true').lower() == 'true'
SYNC_CUSTOM_RULES = os.environ.get('SYNC_CUSTOM_RULES', 'true').lower() == 'true'
SYNC_GENERAL_SETTINGS = os.environ.get('SYNC_GENERAL_SETTINGS', 'true').lower() == 'true'
SYNC_DNS_SETTINGS = os.environ.get('SYNC_DNS_SETTINGS', 'true').lower() == 'true'
SYNC_ENCRYPTION_SETTINGS = os.environ.get('SYNC_ENCRYPTION_SETTINGS', 'false').lower() == 'true'

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

    response = requests.post('{}/control/login'.format(url), data=json.dumps(creds), headers=common.REQUEST_HEADERS)

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
            # Since a bunch of things use filtering status, only retrieve it once per loop to reduce API calls
            primary_filtering_status = common.get_response('{}/control/filtering/status'.format(ADGUARD_PRIMARY), primary_cookie)
            secondary_filtering_status = common.get_response('{}/control/filtering/status'.format(ADGUARD_SECONDARY), secondary_cookie)

            # Reconcile entries
            if SYNC_ENTRIES:
                entries.reconcile(ADGUARD_PRIMARY, ADGUARD_SECONDARY, primary_cookie, secondary_cookie)

            # Reconcile blocked services
            if SYNC_BLOCKED_SERVICES:
                blocked_services.reconcile(ADGUARD_PRIMARY, ADGUARD_SECONDARY, primary_cookie, secondary_cookie)

            # Reconcile block/allow lists
            if SYNC_BLOCK_ALLOW_LISTS:
                block_allow_lists.reconcile(primary_filtering_status, secondary_filtering_status, ADGUARD_SECONDARY, secondary_cookie)

            # Reconcile custom rules
            if SYNC_CUSTOM_RULES:
                custom_rules.reconcile(primary_filtering_status, secondary_filtering_status, ADGUARD_SECONDARY, secondary_cookie)

            # Reconcile general settings
            if SYNC_GENERAL_SETTINGS:
                general.reconcile(primary_filtering_status, secondary_filtering_status, ADGUARD_PRIMARY, primary_cookie, ADGUARD_SECONDARY, secondary_cookie)

            # Reconcile DNS settings
            if SYNC_DNS_SETTINGS:
                dns.reconcile(ADGUARD_PRIMARY, primary_cookie, ADGUARD_SECONDARY, secondary_cookie)

            # Reconcile encrypting settings
            if SYNC_ENCRYPTION_SETTINGS:
                encryption.reconcile(ADGUARD_PRIMARY, primary_cookie, ADGUARD_SECONDARY, secondary_cookie)

        except UnauthenticatedError:
            primary_cookie = get_login_cookie(ADGUARD_PRIMARY, ADGUARD_USER, ADGUARD_PASS)
            secondary_cookie = get_login_cookie(ADGUARD_SECONDARY, SECONDARY_ADGUARD_USER, SECONDARY_ADGUARD_PASS)

            if primary_cookie is None or secondary_cookie is None:
                exit(1)

        except SystemError:
            print('ERROR: Not able to reach AdGuard. Is it running?')

        time.sleep(REFRESH_INTERVAL_SECS)
