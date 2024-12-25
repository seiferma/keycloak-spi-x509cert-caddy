package io.github.seiferma.keycloak.spi.x509cert.caddy;

import org.keycloak.common.util.PemException;
import org.keycloak.services.x509.NginxProxyTrustedClientCertificateLookup;

import java.security.cert.X509Certificate;

public class CaddyProxyTrustedClientCertificateLookup extends NginxProxyTrustedClientCertificateLookup {
    public CaddyProxyTrustedClientCertificateLookup(String sslClientCertHttpHeader, String sslCertChainHttpHeaderPrefix, int certificateChainLength) {
        super(sslClientCertHttpHeader, sslCertChainHttpHeaderPrefix, certificateChainLength);
    }

    @Override
    public X509Certificate decodeCertificateFromPem(String pem) throws PemException {
        return CaddyProxySslClientCertificateLookupHelper.decodeCertificateFromHeaderValue(pem);
    }
}
