import requests
import json
import common
from exceptions import UnauthenticatedError, SystemError


def _get_entries(url, cookie):
    """
    Retrieves all existing entries from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """

    return common.get_response('{}/control/rewrite/list'.format(url), cookie)


def _update_entries(url, cookie, sync_entries):
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
            response = requests.post('{}/control/rewrite/add'.format(url), cookies=cookies, data=json.dumps(data), headers=common.REQUEST_HEADERS)
            if response.status_code == 403:
                raise UnauthenticatedError
            elif response.status_code != 200:
                raise SystemError

        elif entry['action'] == 'DEL':
            print("  - Deleting entry ({} => {})".format(entry['domain'], entry['answer']))
            data = {
                'domain': entry['domain'],
                'answer': entry['answer']
            }
            response = requests.post('{}/control/rewrite/delete'.format(url), cookies=cookies, data=json.dumps(data), headers=common.REQUEST_HEADERS)
            if response.status_code == 403:
                raise UnauthenticatedError
            elif response.status_code != 200:
                raise SystemError

def reconcile(adguard_primary, adguard_secondary, primary_cookie, secondary_cookie):
    primary_entries = _get_entries(adguard_primary, primary_cookie)
    secondary_entries = _get_entries(adguard_secondary, secondary_cookie)

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

    _update_entries(adguard_secondary, secondary_cookie, sync_entries)