import requests
import os
import json
import time
from exceptions import UnauthenticatedError


def _get_block_white_lists(url, cookie):
    """
    Retrieves all existing blocklists from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """
    cookies = {
        'agh_session': cookie
    }

    formatted_block_white_lists = {
        'blocklists': {},
        'whitelists': {}
    }

    response = requests.get('{}/control/filtering/status'.format(url), cookies=cookies)

    if response.status_code == 403:
        raise UnauthenticatedError

    resp_obj = json.loads(response.text)
    blocklist_array = resp_obj['filters']

    if blocklist_array is not None:
        for blocklist in blocklist_array:
            formatted_block_white_lists['blocklists'][blocklist['url']] = {
                'id': blocklist['id'],
                'name': blocklist['name'],
                'url': blocklist['url'],
                'enabled': blocklist['enabled']
            }

    whitelist_array = resp_obj['whitelist_filters']

    if whitelist_array is not None:
        for whitelist in whitelist_array:
            formatted_block_white_lists['whitelists'][whitelist['url']] = {
                'id': whitelist['id'],
                'name': whitelist['name'],
                'url': whitelist['url'],
                'enabled': whitelist['enabled']
            }

    return formatted_block_white_lists


def _update_block_white_lists(url, cookie, sync_block_white_lists):
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

    # Perform deletes first to avoid any conflicts since URLs cannot exist in both.
    for del_whitelist in sync_block_white_lists['whitelists']['del']:
        print("  - Deleting whitelist entry ({})".format(del_whitelist['url']))
        data = {
            'url': del_whitelist['url'],
            'whitelist': True
        }
        response = requests.post('{}/control/filtering/remove_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError

    for del_blocklist in sync_block_white_lists['blocklists']['del']:
        print("  - Deleting blocklist entry ({})".format(del_blocklist['url']))
        data = {
            'url': del_blocklist['url'],
            'whitelist': False
        }
        response = requests.post('{}/control/filtering/remove_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError

    # Perform adds second
    for add_whitelist in sync_block_white_lists['whitelists']['add']:
        print("  - Adding whitelist entry ({})".format(add_whitelist['url']))
        data = {
            'name': add_whitelist['name'],
            'url': add_whitelist['url'],
            'whitelist': True
        }
        response = requests.post('{}/control/filtering/add_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError

    for add_blocklist in sync_block_white_lists['blocklists']['add']:
        print("  - Adding blocklist entry ({})".format(add_blocklist['url']))
        data = {
            'name': add_blocklist['name'],
            'url': add_blocklist['url'],
            'whitelist': False
        }
        response = requests.post('{}/control/filtering/add_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError
    
    # Modify any existing out of sync entry
    for mod in sync_block_white_lists['mods']:
        data = {
            'url': mod['url'],
            'data': {
                'name': mod['name'],
                'url': mod['url'],
                'enabled': mod['enabled']
            },
            'whitelist': mod['whitelist']
        }

        print("  - Updating modified entry ({})".format(mod['url']))
        response = requests.post('{}/control/filtering/set_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError


def reconcile(adguard_primary, adguard_secondary, primary_cookie, secondary_cookie):
    """
    Reconcile blocklists from primary to secondary Adguards.
    Uses the URL as the unique identifier between instances.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_block_white_lists = _get_block_white_lists(adguard_primary, primary_cookie)
    secondary_block_white_lists = _get_block_white_lists(adguard_secondary, secondary_cookie)

    sync_block_white_lists = {
        'blocklists': {
            'add': [],
            'del': []
        },
        'whitelists': {
            'add': [],
            'del': []
        },
        'mods': []
    }


    for k,v in primary_block_white_lists['blocklists'].items():
        if k not in secondary_block_white_lists['blocklists']:
            sync_block_white_lists['blocklists']['add'].append({
                'url': v['url'],
                'name': v['name'],
                'enabled': v['enabled']
            })
        else:
            if primary_block_white_lists['blocklists'][k]['enabled'] != secondary_block_white_lists['blocklists'][k]['enabled'] or primary_block_white_lists['blocklists'][k]['name'] != secondary_block_white_lists['blocklists'][k]['name']:
                sync_block_white_lists['mods'].append({
                    'enabled': primary_block_white_lists['blocklists'][k]['enabled'],
                    'name': primary_block_white_lists['blocklists'][k]['name'],
                    'url': k,
                    'whitelist': False
                })

    for k,v in secondary_block_white_lists['blocklists'].items():
        if k not in primary_block_white_lists['blocklists']:
            sync_block_white_lists['blocklists']['del'].append({
                'url': v['url']
            })

    for k,v in primary_block_white_lists['whitelists'].items():
        if k not in secondary_block_white_lists['whitelists']:
            sync_block_white_lists['whitelists']['add'].append({
                'url': v['url'],
                'name': v['name'],
                'enabled': v['enabled']
            })
        else:
            if primary_block_white_lists['whitelists'][k]['enabled'] != secondary_block_white_lists['whitelists'][k]['enabled'] or primary_block_white_lists['whitelists'][k]['name'] != secondary_block_white_lists['whitelists'][k]['name']:
                sync_block_white_lists['mods'].append({
                    'enabled': primary_block_white_lists['whitelists'][k]['enabled'],
                    'name': primary_block_white_lists['whitelists'][k]['name'],
                    'url': k,
                    'whitelist': True
                })

    for k,v in secondary_block_white_lists['whitelists'].items():
        if k not in primary_block_white_lists['whitelists']:
            sync_block_white_lists['whitelists']['del'].append({
                'url': v['url']
            })

    _update_block_white_lists(adguard_secondary, secondary_cookie, sync_block_white_lists)