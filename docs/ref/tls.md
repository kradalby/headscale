# Running the service via TLS (optional)

This page is about the certificate of headscale itself. Nodes can get certificates for their own names with
`tailscale cert`, see [TLS certificates for nodes](dns.md#tls-certificates-for-nodes).

## Bring your own certificate

Headscale can be configured to expose its web service via TLS. To configure the certificate and key file manually, set the `tls.cert_path` and `tls.key_path` configuration parameters. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```yaml title="config.yaml"
tls:
  cert_path: ""
  key_path: ""
```

The certificate should contain the full chain, else some clients, like the Tailscale Android client, will reject it.

## Let's Encrypt / ACME

To get a certificate automatically via [Let's Encrypt](https://letsencrypt.org/), set `tls.acme.hostname` to the desired certificate hostname. This name must resolve to the IP address(es) headscale is reachable on (i.e., it must correspond to the `server_url` configuration parameter). The certificate and ACME account credentials will be stored in the directory configured in `tls.acme.cache_dir`. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```yaml title="config.yaml"
tls:
  acme:
    hostname: ""
    challenge_type: HTTP-01
    http_listen: ":http"
    cache_dir: /var/lib/headscale/cache
    # url: https://acme-v02.api.letsencrypt.org/directory
    # email: ""
```

!!! note "Older configuration keys"

    The flat keys `tls_cert_path`, `tls_key_path`, `tls_letsencrypt_hostname`, `tls_letsencrypt_challenge_type`,
    `tls_letsencrypt_listen`, `tls_letsencrypt_cache_dir`, `acme_url` and `acme_email` still work, with a warning.
    Keys under `tls` take precedence.

### Challenge types

Headscale supports three values for `tls.acme.challenge_type`: `HTTP-01` (default), `TLS-ALPN-01` and `DNS-01`.

#### HTTP-01

For `HTTP-01`, headscale must be reachable on port 80 for the Let's Encrypt automated validation, in addition to whatever port is configured in `listen_addr`. By default, headscale listens on port 80 on all local IPs for Let's Encrypt automated validation. In this mode headscale also answers `TLS-ALPN-01` validation on `listen_addr`, so a headscale reachable on port 443 also passes without port 80.

!!! warning "`listen_addr` cannot also be port 80"

    `listen_addr` and `tls.acme.http_listen` must not bind the same TCP socket. A common mistake is setting `listen_addr: 0.0.0.0:80` together with `tls.acme.hostname` — both endpoints try to claim port 80, and the second bind fails with `address already in use` even though no other process is involved. Headscale validates this at startup and refuses to launch with a `Fatal config error: listen_addr and tls.acme.http_listen would bind the same TCP socket` message. Use `listen_addr: 0.0.0.0:443` (or any non-80 port) when HTTP-01 is enabled.

If you need to change the ip and/or port used by headscale for the Let's Encrypt validation process, set `tls.acme.http_listen` to the appropriate value. This can be handy if you are running headscale as a non-root user (or can't run `setcap`). Keep in mind, however, that Let's Encrypt will _only_ connect to port 80 for the validation callback, so if you change `tls.acme.http_listen` you will also need to configure something else (e.g. a firewall rule) to forward the traffic from port 80 to the ip:port combination specified in `tls.acme.http_listen`.

#### TLS-ALPN-01

For `TLS-ALPN-01`, headscale listens on the ip:port combination defined in `listen_addr`. Let's Encrypt will _only_ connect to port 443 for the validation callback, so if `listen_addr` is not set to port 443, something else (e.g. a firewall rule) will be required to forward the traffic from port 443 to the ip:port combination specified in `listen_addr`.

#### DNS-01

For `DNS-01`, headscale publishes a TXT record through a DNS provider and needs no open port for the validation. This works for a headscale that is not reachable from the internet. Configure the provider under `dns.challenge`, the same one used for [node certificates](dns.md#tls-certificates-for-nodes):

```yaml title="config.yaml"
tls:
  acme:
    hostname: headscale.example.com
    challenge_type: DNS-01
dns:
  challenge:
    provider:
      name: cloudflare
      api_token_path: /run/credentials/headscale.service/cloudflare-token
```

The zone of `tls.acme.hostname` is found by a DNS lookup. The provider's credentials must be able to write to that zone, which may not be the zone of `dns.base_domain`.

### Technical description

Headscale uses [CertMagic](https://github.com/caddyserver/certmagic), the library behind the Caddy web server, to obtain and renew certificates via the [ACME protocol](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment). The following can be expected:

- Certificates provided from Let's Encrypt have a validity of 3 months from date issued.
- Renewals start when a third of the validity remains, or earlier when the CA asks for it ([ACME Renewal Information](https://datatracker.ietf.org/doc/rfc9773/)).
- A failed attempt is retried with increasing delays; a certificate already obtained keeps being served meanwhile.
- Log lines from the library are logged with `logger=acme`.

!!! note "Upgrading from headscale 0.29 or older"

    Older versions stored the certificate in a different format. On the first start, headscale registers a new ACME
    account and obtains a new certificate. The old files are left in place.

#### Checking certificate expiry

If you want to validate that certificate renewal completed successfully, this can be done either manually, or through external monitoring software. Two examples of doing this manually:

1. Open the URL for your headscale server in your browser of choice, and manually inspecting the expiry date of the certificate you receive.
1. Or, check remotely from CLI using `openssl`:

```console
$ openssl s_client -servername [hostname] -connect [hostname]:443 | openssl x509 -noout -dates
(...)
notBefore=Feb  8 09:48:26 2024 GMT
notAfter=May  8 09:48:25 2024 GMT
```
