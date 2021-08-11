import requests
import os
import json
import time

ADGUARD_PRIMARY = os.environ['ADGUARD_PRIMARY']
ADGUARD_SECONDARY = os.environ['ADGUARD_SECONDARY']

ADGUARD_USER = os.environ['ADGUARD_USER']
ADGUARD_PASS = os.environ['ADGUARD_PASS']

# Optional, use if your secondary AdGuard has different credentials
SECONDARY_ADGUARD_USER = os.environ.get('SECONDARY_ADGUARD_USER', ADGUARD_USER)
SECONDARY_ADGUARD_PASS = os.environ.get('SECONDARY_ADGUARD_PASS', ADGUARD_PASS)

REFRESH_INTERVAL_SECS = int(os.environ.get('REFRESH_INTERVAL_SECS', '60'))


class UnauthenticatedError(Exception):
    pass


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


def get_entries(url, cookie):
    """
    Retrieves all existing entries from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """
    cookies = {
        'agh_session': cookie
    }
    response = requests.get('{}/control/rewrite/list'.format(url), cookies=cookies)

    if response.status_code == 403:
        raise UnauthenticatedError

    entry_array = json.loads(response.text)

    return entry_array


def update_entries(url, cookie, sync_entries):
    """
    Update entries from your primary to secondary AdGuard.

    ADD: Will add the entry with the domain pointing to IP.
    UPDATE: Will update existing entry to point the domain to the new IP.
    DEL: Will delete the existing entry from secondary AdGuard.
    :param url: URL of the Secondary AdGuard
    :param cookie: Secondary AdGuard Auth Cookie.
    :param sync_entries: Array of entries to be sync.
    :return: None
    """

    cookies = {
        'agh_session': cookie
    }

    for entry in sync_entries:
        if entry['action'] == 'ADD':
            print("  - Adding entry ({} => {})".format(entry['domain'], entry['answer']))
            data = {
                'domain': entry['domain'],
                'answer': entry['answer']
            }
            response = requests.post('{}/control/rewrite/add'.format(url), cookies=cookies, data=json.dumps(data))
            if response.status_code == 403:
                raise UnauthenticatedError

        elif entry['action'] == 'DEL':
            print("  - Deleting entry ({} => {})".format(entry['domain'], entry['answer']))
            data = {
                'domain': entry['domain'],
                'answer': entry['answer']
            }
            response = requests.post('{}/control/rewrite/delete'.format(url), cookies=cookies, data=json.dumps(data))
            if response.status_code == 403:
                raise UnauthenticatedError


if __name__ == '__main__':
    print("Running Adguard Sync for '{}' => '{}'..".format(ADGUARD_PRIMARY, ADGUARD_SECONDARY))

    # Get initial login cookie
    primary_cookie = get_login_cookie(ADGUARD_PRIMARY, ADGUARD_USER, ADGUARD_PASS)
    secondary_cookie = get_login_cookie(ADGUARD_SECONDARY, SECONDARY_ADGUARD_USER, SECONDARY_ADGUARD_PASS)

    if primary_cookie is None or secondary_cookie is None:
        exit(1)

    while True:
        try:
            primary_entries = get_entries(ADGUARD_PRIMARY, primary_cookie)
            secondary_entries = get_entries(ADGUARD_SECONDARY, secondary_cookie)

            sync_entries = []

            for e in primary_entries:
                if e not in secondary_entries:
                    sync_entries.append({
                        'action': 'ADD',
                        'domain': e['domain'],
                        'answer': e['answer']
                    })

            for s in secondary_entries:
                if s not in primary_entries:
                    sync_entries.append({
                        'action': 'DEL',
                        'domain': s['domain'],
                        'answer': s['answer']
                    })

            update_entries(ADGUARD_SECONDARY, secondary_cookie, sync_entries)

        except UnauthenticatedError:
            primary_cookie = get_login_cookie(ADGUARD_PRIMARY, ADGUARD_USER, ADGUARD_PASS)
            secondary_cookie = get_login_cookie(ADGUARD_SECONDARY, SECONDARY_ADGUARD_USER, SECONDARY_ADGUARD_PASS)

            if primary_cookie is None or secondary_cookie is None:
                exit(1)

        time.sleep(REFRESH_INTERVAL_SECS)
