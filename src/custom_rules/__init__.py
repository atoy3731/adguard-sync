import requests
import os
import json
import time
import common
from exceptions import UnauthenticatedError, SystemError


def _get_custom_rules(filtering_status):
    """
    Retrieves all existing blocked services from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """
    
    custom_rules_array = filtering_status['user_rules']
    custom_rules_str = '\n'.join(custom_rules_array)

    return {
        'array': custom_rules_array,
        'string': custom_rules_str
    }


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

    body = {
        'rules': custom_rules
    }

    print("  - Syncing custom rules")
    response = requests.post('{}/control/filtering/set_rules'.format(url), headers=common.REQUEST_HEADERS, cookies=cookies, data=json.dumps(body))
    
    if response.status_code == 403:
        raise UnauthenticatedError
    elif response.status_code != 200:
        raise SystemError


def reconcile(primary_filtering_status, secondary_filtering_status, adguard_secondary, secondary_cookie):
    """
    Reconcile blocked services from primary to secondary Adguards.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_custom_rules = _get_custom_rules(primary_filtering_status)
    secondary_custom_rules = _get_custom_rules(secondary_filtering_status)

    if primary_custom_rules['string'] != secondary_custom_rules['string']:
        _update_custom_rules(adguard_secondary, secondary_cookie, primary_custom_rules['array'])