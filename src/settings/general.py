import requests
from exceptions import UnauthenticatedError, SystemError
import common
import json


def _get_general_settings(filtering_status, url, cookie):
    """
    Retrieves all general settings from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """

    settings = {}

    # Retrieve overarching protection setting
    response = common.get_response('{}/control/status'.format(url), cookie)
    settings['protection_enabled'] = response['protection_enabled']

    # Retrieve safebrowsing setting
    response = common.get_response('{}/control/safebrowsing/status'.format(url), cookie)
    settings['safebrowsing'] = response['enabled']

    # Retrieve safesearch setting
    response = common.get_response('{}/control/safesearch/status'.format(url), cookie)
    settings['safesearch'] = response['enabled']

    # Retrieve parental setting
    response = common.get_response('{}/control/parental/status'.format(url), cookie)
    settings['parental'] = response['enabled']

    # Retrieve querylog setting
    response = common.get_response('{}/control/querylog_info'.format(url), cookie)
    settings['querylog_info'] = response

    # Retrieve stats setting
    response = common.get_response('{}/control/stats_info'.format(url), cookie)
    settings['stats_info'] = response

    # Set relevant filtering status
    settings['filtering'] = {
        'enabled': filtering_status['enabled'],
        'interval': filtering_status['interval']
    }

    return settings


def _update_enable_setting(setting, enabled, url, cookie):
    """
    Update enable/disable setting in secondary AdGuard.
    :param setting: Name of the setting to be added to URL
    :param enabled: Bool if the setting should be enabled/disabled
    :param url: URL of the Secondary AdGuard
    :param cookie: Secondary AdGuard Auth Cookie.
    :return: None
    """
    cookies = {
        'agh_session': cookie
    }

    print("  - Updating {} setting".format(setting))
    if enabled:
        response = requests.post('{}/control/{}/enable'.format(url, setting), cookies=cookies)
    else:
        response = requests.post('{}/control/{}/disable'.format(url, setting), cookies=cookies)

    if response.status_code == 403:
        raise UnauthenticatedError
    elif response.status_code != 200:
        raise SystemError

def _update_protection_enabled(enabled, url, cookie):
    """
    Update enable/disable of overarching protection in secondary AdGuard.
    :param enabled: Bool if the setting should be enabled/disabled
    :param url: URL of the Secondary AdGuard
    :param cookie: Secondary AdGuard Auth Cookie.
    :return: None
    """
    cookies = {
        'agh_session': cookie
    }

    data = {
        'protection_enabled': enabled
    }
    
    if enabled:
        print("  - Enabling global protection")
    else:
        print("  - Disabling global protection")
    
    response = requests.post('{}/control/dns_config'.format(url), data=json.dumps(data), headers=common.REQUEST_HEADERS, cookies=cookies)

    if response.status_code == 403:
        raise UnauthenticatedError
    elif response.status_code != 200:
        raise SystemError

def reconcile(primary_filtering_status, secondary_filtering_status, adguard_primary, primary_cookie, adguard_secondary, secondary_cookie):
    """
    Reconcile blocked services from primary to secondary Adguards.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_general_settings = _get_general_settings(primary_filtering_status, adguard_primary, primary_cookie)
    secondary_general_settings = _get_general_settings(secondary_filtering_status, adguard_secondary, secondary_cookie)

    # Overarching protection
    if primary_general_settings['protection_enabled'] != secondary_general_settings['protection_enabled']:
        _update_protection_enabled(primary_general_settings['protection_enabled'], adguard_secondary, secondary_cookie)

    # Safesearch Update
    if primary_general_settings['safesearch'] != secondary_general_settings['safesearch']:
        _update_enable_setting('safesearch', primary_general_settings['safesearch'], adguard_secondary, secondary_cookie)

    # Safebrowsing Update
    if primary_general_settings['safebrowsing'] != secondary_general_settings['safebrowsing']:
        _update_enable_setting('safebrowsing', primary_general_settings['safebrowsing'], adguard_secondary, secondary_cookie)

    # Parental Update
    if primary_general_settings['parental'] != secondary_general_settings['parental']:
        _update_enable_setting('parental', primary_general_settings['parental'], adguard_secondary, secondary_cookie)

    # Updating other settings, a little more complicated so passing all logic to function
    common.update_settings('filtering', primary_general_settings['filtering'], secondary_general_settings['filtering'], '{}/control/filtering/config'.format(adguard_secondary), secondary_cookie)
    common.update_settings('querylog', primary_general_settings['querylog_info'], secondary_general_settings['querylog_info'], '{}/control/querylog_config'.format(adguard_secondary), secondary_cookie)
    common.update_settings('status', primary_general_settings['stats_info'], secondary_general_settings['stats_info'], '{}/control/stats_config'.format(adguard_secondary), secondary_cookie)
