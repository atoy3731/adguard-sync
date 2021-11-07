# AdGuard Sync

![Docker](https://github.com/atoy3731/adguard-sync/workflows/Docker/badge.svg)


This project will sync entries between a Primary and Secondary AdGuard Home instance using the API.

This is useful if you're dependent on local DNS and want to ensure relative High Availability.

### How to Run

AdGuard Sync is packaged as a Docker image and can be ran anywhere with access to your instances, though it is advisable to run this on the same instance that is running your Primary Adguard instance. This makes your primary instance the "source of truth" for local DNS, but allows your secondary instance to stay in sync as a fallback. Once running, set your router DNS to point to both your primary and secondary. You can update the `docker-compose.yaml` file with your values based on the following:

| Variable | Required | Description | Default |
|---|---|---|---|
| ADGUARD_PRIMARY | Yes | Primary base URL for the primary AdGuard instance (ie. http://dns01.example.com) | N/A |
| ADGUARD_SECONDARY | Yes | Secondary base URL for the primary AdGuard instance (ie. http://dns02.example.com) | N/A |
| ADGUARD_USER | Yes | Username to log into your AdGuard instances. | N/A |
| ADGUARD_PASS | Yes | Password to log into your AdGuard instances. | N/A |
| SECONDARY_ADGUARD_USER | No | Username to log into your secondary AdGuard instance. Only necessary if credentials are different between primary and secondary | Value of 'ADGUARD_USER' |
| SECONDARY_ADGUARD_PASS | No | Password to log into your secondary AdGuard instance. Only necessary if credentials are different between primary and secondary | Value of 'ADGUARD_PASS' |
| REFRESH_INTERVAL_SECS | No | Frequency in seconds to refresh entries. | 60 |
| SYNC_ENTRIES | No | If 'true', will sync rewrite entries. | true |
| SYNC_BLOCKED_SERVICES | No | If 'true', will sync blocked services. | true |
| SYNC_BLOCK_ALLOW_LISTS | No | If 'true', will sync block/allow lists. | true |
| SYNC_CUSTOM_RULES | No | If 'true', will sync custom rules. | true |
| SYNC_GENERAL_SETTINGS | No | If 'true', will sync general settings. | true |
| SYNC_DNS_SETTINGS | No | If 'true', will sync DNS settings. | true |
| SYNC_ENCRYPTION_SETTINGS | No | If 'true', will sync encrypt settings. | false |

Once you've updated the file and ensure you have `docker` and `docker-compose` installed, run the following in the root directory:

```bash
docker-compose up -d
```

You can check on the status of your newly running pod with:

```bash
docker-compose logs
```

**NOTE:** The container is set to automatically restart when the docker daemon restarts.

### Encryption Syncing with Certifications/Keys

If you plan to sync encryption settings across environments and you're using paths for certificates/keys, you *must make sure the files exist in both primary and secondary AdGuard instances*! Given this, `SYNC_ENCRYPTION_SETTINGS` is defaulted to `false` as a safety measure.