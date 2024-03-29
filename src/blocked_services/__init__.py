import requests
import json
import common
from exceptions import UnauthenticatedError, SystemError


def _get_blocked_services(url, cookie):
    """
    Retrieves all existing blocked services from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """

    return common.get_response('{}/control/blocked_services/list'.format(url), cookie)


def _update_blocked_services(url, cookie, sync_blocked_services):
    """
    Update blocked services from your primary to secondary AdGuard.
    :param url: URL of the Secondary AdGuard
    :param cookie: Secondary AdGuard Auth Cookie.
    :param sync_blocked_services: Array of entries to be sync.
    :return: None
    """

    cookies = {
        'agh_session': cookie
    }

    print("  - Syncing blocked services")
    response = requests.post('{}/control/blocked_services/set'.format(url), cookies=cookies, data=json.dumps(sync_blocked_services), headers=common.REQUEST_HEADERS)
    
    if response.status_code == 403:
        raise UnauthenticatedError
    elif response.status_code != 200:
        raise SystemError


def reconcile(adguard_primary, adguard_secondary, primary_cookie, secondary_cookie):
    """
    Reconcile blocked services from primary to secondary Adguards.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_blocked_services = _get_blocked_services(adguard_primary, primary_cookie)
    secondary_blocked_services = _get_blocked_services(adguard_secondary, secondary_cookie)

    for bs in primary_blocked_services:
        if bs not in secondary_blocked_services:
            _update_blocked_services(adguard_secondary, secondary_cookie, primary_blocked_services)
            break

    for bs in secondary_blocked_services:
        if bs not in primary_blocked_services:
            _update_blocked_services(adguard_secondary, secondary_cookie, primary_blocked_services)
            break
    