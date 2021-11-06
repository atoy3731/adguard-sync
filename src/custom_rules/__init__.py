import requests
import os
import json
import time
from exceptions import UnauthenticatedError


def _get_custom_rules(url, cookie):
    """
    Retrieves all existing blocked services from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """
    cookies = {
        'agh_session': cookie
    }

    response = requests.get('{}/control/filtering/status'.format(url), cookies=cookies)

    if response.status_code == 403:
        raise UnauthenticatedError

    resp = json.loads(response.text)
    custom_rules_array = resp['user_rules']
    custom_rules_str = '\n'.join(custom_rules_array)

    return custom_rules_str


def _update_custom_rules(url, cookie, custom_rules):
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

    print("  - Syncing custom rules")
    response = requests.post('{}/control/filtering/set_rules'.format(url), cookies=cookies, data=custom_rules)
    
    if response.status_code == 403:
        raise UnauthenticatedError


def reconcile(adguard_primary, adguard_secondary, primary_cookie, secondary_cookie):
    """
    Reconcile blocked services from primary to secondary Adguards.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_custom_rules = _get_custom_rules(adguard_primary, primary_cookie)
    secondary_custom_rules = _get_custom_rules(adguard_secondary, secondary_cookie)

    if primary_custom_rules != secondary_custom_rules:
        _update_custom_rules(adguard_secondary, secondary_cookie, primary_custom_rules)