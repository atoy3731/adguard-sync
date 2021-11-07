import requests
import json
from exceptions import UnauthenticatedError, SystemError


def _get_block_allow_lists(filtering_status):
    """
    Retrieves all existing blocklists from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """
    formatted_block_allow_lists = {
        'blocklists': {},
        'allowlists': {}
    }

    blocklist_array = filtering_status['filters']

    if blocklist_array is not None:
        for blocklist in blocklist_array:
            formatted_block_allow_lists['blocklists'][blocklist['url']] = {
                'id': blocklist['id'],
                'name': blocklist['name'],
                'url': blocklist['url'],
                'enabled': blocklist['enabled']
            }

    allowlist_array = filtering_status['whitelist_filters']

    if allowlist_array is not None:
        for allowlist in allowlist_array:
            formatted_block_allow_lists['allowlists'][allowlist['url']] = {
                'id': allowlist['id'],
                'name': allowlist['name'],
                'url': allowlist['url'],
                'enabled': allowlist['enabled']
            }

    return formatted_block_allow_lists


def _update_block_allow_lists(url, cookie, sync_block_allow_lists):
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
    for del_allowlist in sync_block_allow_lists['allowlists']['del']:
        print("  - Deleting allowlist entry ({})".format(del_allowlist['url']))
        data = {
            'url': del_allowlist['url'],
            'whitelist': True
        }
        response = requests.post('{}/control/filtering/remove_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError
        elif response.status_code != 200:
            raise SystemError

    for del_blocklist in sync_block_allow_lists['blocklists']['del']:
        print("  - Deleting blocklist entry ({})".format(del_blocklist['url']))
        data = {
            'url': del_blocklist['url'],
            'whitelist': False
        }
        response = requests.post('{}/control/filtering/remove_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError
        elif response.status_code != 200:
            raise SystemError

    # Perform adds second
    for add_allowlist in sync_block_allow_lists['allowlists']['add']:
        print("  - Adding allowlist entry ({})".format(add_allowlist['url']))
        data = {
            'name': add_allowlist['name'],
            'url': add_allowlist['url'],
            'whitelist': True
        }
        response = requests.post('{}/control/filtering/add_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError
        elif response.status_code != 200:
            raise SystemError

    for add_blocklist in sync_block_allow_lists['blocklists']['add']:
        print("  - Adding blocklist entry ({})".format(add_blocklist['url']))
        data = {
            'name': add_blocklist['name'],
            'url': add_blocklist['url'],
            'whitelist': False
        }
        response = requests.post('{}/control/filtering/add_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError
        elif response.status_code != 200:
            raise SystemError
    
    # Modify any existing out of sync entry
    for mod in sync_block_allow_lists['mods']:
        data = {
            'url': mod['url'],
            'data': {
                'name': mod['name'],
                'url': mod['url'],
                'enabled': mod['enabled']
            },
            'whitelist': mod['allowlist']
        }

        print("  - Updating modified entry ({})".format(mod['url']))
        response = requests.post('{}/control/filtering/set_url'.format(url), cookies=cookies, data=json.dumps(data))
        
        if response.status_code == 403:
            raise UnauthenticatedError
        elif response.status_code != 200:
            raise SystemError


def reconcile(primary_filtering_status, secondary_filtering_status, adguard_secondary, secondary_cookie):
    """
    Reconcile blocklists from primary to secondary Adguards.
    Uses the URL as the unique identifier between instances.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_block_allow_lists = _get_block_allow_lists(primary_filtering_status)
    secondary_block_allow_lists = _get_block_allow_lists(secondary_filtering_status)

    sync_block_allow_lists = {
        'blocklists': {
            'add': [],
            'del': []
        },
        'allowlists': {
            'add': [],
            'del': []
        },
        'mods': []
    }


    for k,v in primary_block_allow_lists['blocklists'].items():
        if k not in secondary_block_allow_lists['blocklists']:
            sync_block_allow_lists['blocklists']['add'].append({
                'url': v['url'],
                'name': v['name'],
                'enabled': v['enabled']
            })
        else:
            if primary_block_allow_lists['blocklists'][k]['enabled'] != secondary_block_allow_lists['blocklists'][k]['enabled'] or primary_block_allow_lists['blocklists'][k]['name'] != secondary_block_allow_lists['blocklists'][k]['name']:
                sync_block_allow_lists['mods'].append({
                    'enabled': primary_block_allow_lists['blocklists'][k]['enabled'],
                    'name': primary_block_allow_lists['blocklists'][k]['name'],
                    'url': k,
                    'allowlist': False
                })

    for k,v in secondary_block_allow_lists['blocklists'].items():
        if k not in primary_block_allow_lists['blocklists']:
            sync_block_allow_lists['blocklists']['del'].append({
                'url': v['url']
            })

    for k,v in primary_block_allow_lists['allowlists'].items():
        if k not in secondary_block_allow_lists['allowlists']:
            sync_block_allow_lists['allowlists']['add'].append({
                'url': v['url'],
                'name': v['name'],
                'enabled': v['enabled']
            })
        else:
            if primary_block_allow_lists['allowlists'][k]['enabled'] != secondary_block_allow_lists['allowlists'][k]['enabled'] or primary_block_allow_lists['allowlists'][k]['name'] != secondary_block_allow_lists['allowlists'][k]['name']:
                sync_block_allow_lists['mods'].append({
                    'enabled': primary_block_allow_lists['allowlists'][k]['enabled'],
                    'name': primary_block_allow_lists['allowlists'][k]['name'],
                    'url': k,
                    'allowlist': True
                })

    for k,v in secondary_block_allow_lists['allowlists'].items():
        if k not in primary_block_allow_lists['allowlists']:
            sync_block_allow_lists['allowlists']['del'].append({
                'url': v['url']
            })

    _update_block_allow_lists(adguard_secondary, secondary_cookie, sync_block_allow_lists)