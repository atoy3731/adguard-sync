import common

def _get_dns_settings(url, cookie):
    """
    Retrieves all existing blocked services from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """

    settings = {
        'upstream': {},
        'server': {},
        'cache': {},
        'access': {}
    }

    # Retrieve DNS/cache setting
    response = common.get_response('{}/control/dns_info'.format(url), cookie)
    settings['upstream']['upstream_dns'] = response['upstream_dns']
    settings['upstream']['bootstrap_dns'] = response['bootstrap_dns']
    settings['upstream']['local_ptr_upstreams'] = response['local_ptr_upstreams']
    settings['upstream']['resolve_clients'] = response['resolve_clients']
    settings['upstream']['upstream_mode'] = response['upstream_mode']

    settings['server']['blocking_ipv4'] = response['blocking_ipv4']
    settings['server']['blocking_ipv6'] = response['blocking_ipv6']
    settings['server']['blocking_mode'] = response['blocking_mode']
    settings['server']['disable_ipv6'] = response['disable_ipv6']
    settings['server']['dnssec_enabled'] = response['dnssec_enabled']
    settings['server']['edns_cs_enabled'] = response['edns_cs_enabled']
    settings['server']['ratelimit'] = response['ratelimit']

    settings['cache']['cache_size'] =response['cache_size']
    settings['cache']['cache_ttl_max'] = response['cache_ttl_max']
    settings['cache']['cache_ttl_min'] = response['cache_ttl_min']

    # Retrieve safesearch setting
    response = common.get_response('{}/control/access/list'.format(url), cookie)
    settings['access'] = response

    return settings


def reconcile(adguard_primary, primary_cookie, adguard_secondary, secondary_cookie):
    """
    Reconcile blocked services from primary to secondary Adguards.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_dns_settings = _get_dns_settings(adguard_primary, primary_cookie)
    secondary_dns_settings = _get_dns_settings(adguard_secondary, secondary_cookie)

    common.update_settings('DNS upstream', primary_dns_settings['upstream'], secondary_dns_settings['upstream'], '{}/control/dns_config'.format(adguard_secondary), secondary_cookie)
    common.update_settings('DNS server', primary_dns_settings['server'], secondary_dns_settings['server'], '{}/control/dns_config'.format(adguard_secondary), secondary_cookie) 
    common.update_settings('DNS cache', primary_dns_settings['cache'], secondary_dns_settings['cache'], '{}/control/dns_config'.format(adguard_secondary), secondary_cookie)
    common.update_settings('access', primary_dns_settings['access'], secondary_dns_settings['access'], '{}/control/access/set'.format(adguard_secondary), secondary_cookie)