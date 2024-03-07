# Simple Mikrotik DDNS

An extremely quick and dirty daemon that queries RouterOS REST endpoint for DHCP leases on-demand and constructs a DNS response. Essentially a poor man's DHCP-based dynamic DNS.

Use at your own risk.

## How to use

1. Create a new user in RouterOS, allow it to read router config and access it via API.
2. Create config similar to this:

    ```toml
    my_zone = "home.arpa" # or other tld, to taste
    username = "rest_user" # routeros username to use API
    password = "mysecretpassword" # password
    hostname = "192.168.0.1" # router IP address or hostname;
    # bear in mind if you use the hostname, you may run into a chicken-and-egg
    # problem
    allow_wildcard = false # will match requests to "foo.bar.host.home.arpa"
    # with "host"; false will require exact match. Default false.
    static_timeout = 86400 # DNS record timeout for static records in seconds;
    # default 1 day

    [static_records] # optional static records host = "address"
    router = "192.168.0.1"

    [name_overrides] # override name based on mac address; NB: case sensitive
    "00:B0:D0:63:C2:26" = "overriden-device-name"
    ```
3. Run the binary: `simple-mikrotik-ddns -c /path/to/config.toml -l 127.0.0.1:53`.

The intention is to run this behind a caching resolver, e.g. Unbound, dnscrypt-proxy, etc, and to point only the local zone to this server. Trying to resolve any other zone will result in SERVFAIL.
