import common

def _get_encryption_settings(url, cookie):
    """
    Retrieves all existing encryption settings from AdGuard.
    :param url: Base AdGuard URL
    :param cookie: Session token
    :return: List of Entries
    """

    # Retrieve encryption setting
    return common.get_response('{}/control/tls/status'.format(url), cookie)


def reconcile(adguard_primary, primary_cookie, adguard_secondary, secondary_cookie):
    """
    Reconcile encryption settings from primary to secondary Adguards.
    :param adguard_primary: URL of primary Adguard.
    :param adguard_secondary: URL of secondardy Adguard.
    :param primary_cookie: Auth cookie for primary Adguard.
    :param secondary_cookie: Auth cookie for secondary Adguard.
    """
    primary_encryption_settings = _get_encryption_settings(adguard_primary, primary_cookie)
    secondary_encryption_settings = _get_encryption_settings(adguard_secondary, secondary_cookie)

    common.update_settings('encryption', primary_encryption_settings, secondary_encryption_settings, '{}/control/tls/configure'.format(adguard_secondary), secondary_cookie)
