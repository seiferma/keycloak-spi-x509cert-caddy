# keycloak-spi-x509cert-caddy

[![Build Status of Main](https://img.shields.io/github/check-runs/seiferma/keycloak-spi-x509cert-caddy/main)](https://github.com/seiferma/keycloak-spi-x509cert-caddy/actions?query=branch%3Amain++)
[![Latest Release](https://img.shields.io/github/v/release/seiferma/keycloak-spi-x509cert-caddy)](https://github.com/seiferma/keycloak-spi-x509cert-caddy/releases/latest)
[![License](https://img.shields.io/github/license/seiferma/keycloak-spi-x509cert-caddy)](https://github.com/seiferma/keycloak-spi-x509cert-caddy/blob/main/LICENSE)

This repository hosts an implementation of the X509 client certificate lookup for Keyloak in combination with a
Caddy reverse proxy.

## How to use

1. Read the [official manual](https://www.keycloak.org/server/reverseproxy#_enabling_client_certificate_lookup)
   (this manual only covers the caddy-specific aspects)
1. Build the jar by running `./gradlew build`
1. Copy the jar (`build/libs/*.jar`) into the `providers` folder of keycloak
1. Configure keycloak
    * `--spi-x509cert-lookup-provider=caddy`
    * `--spi-x509cert-lookup-caddy-ssl-client-cert=X-Client-Cert`
    * `--spi-x509cert-lookup-caddy-trust-proxy-verification=true` (only use this if Caddy already validated the certificate!)
1. Configure Caddy
```
keycloak.example.org {
        tls {
                client_auth {
                        mode request
                }
        }
        vars cert_header ""
        @certavailable vars_regexp {tls_client_certificate_der_base64} .+
        vars @certavailable cert_header {tls_client_certificate_der_base64}
        reverse_proxy https://keycloak:8443 {
                header_up X-Client-Cert {vars.cert_header}
        }
}
```

## Background

This partially addresses an [open issue](https://github.com/keycloak/keycloak/issues/20761) in the keycloak repository
that is about supporting [RFC 9440](https://datatracker.ietf.org/doc/rfc9440/). The implementation only supports the RFC
partially because it only considers the aspects required by Caddy.

**Handling of client certificates in Caddy**
* Caddy supports base64 encoded DER representations of client certificates in the `{tls_client_certificate_der_base64}` variable
* Caddy does not support transmitting the certificate chain of the client certificate

**Handling according to RFC 9440**
* Certificates are given as base64 encoded DER representations delimited by colons
* Certificate chains are transmitted in a header as a comma separated list of certificates (see first point)

**Handling by this implementation**
* Base64 encoded DER representations can be parsed with or without colons used as delimiters
* Certificate chains are not parsed but the logic of the nginx lookup for rebuilding the certificate chain is reused