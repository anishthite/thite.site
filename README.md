# thite.site

Static living index of public `thite.site` apps.

## Refresh locally

```sh
python3 scripts/scan_subdomains.py --domain thite.site --output data/subdomains.json
python3 -m http.server 8000
```

`data/manual-hosts.txt` pins DNS records that certificate transparency misses.
The GitHub Action refreshes `data/subdomains.json` once a day and commits changes.
