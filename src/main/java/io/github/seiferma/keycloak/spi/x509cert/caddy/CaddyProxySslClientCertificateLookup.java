package io.github.seiferma.keycloak.spi.x509cert.caddy;

import org.keycloak.common.util.PemException;
import org.keycloak.services.x509.NginxProxySslClientCertificateLookup;

import java.security.cert.X509Certificate;
import java.util.Set;

public class CaddyProxySslClientCertificateLookup extends NginxProxySslClientCertificateLookup {
    public CaddyProxySslClientCertificateLookup(String sslClientCertHttpHeader, String sslCertChainHttpHeaderPrefix, int certificateChainLength, Set<X509Certificate> intermediateCerts, Set<X509Certificate> trustedRootCerts, boolean isTruststoreLoaded) {
        super(sslClientCertHttpHeader, sslCertChainHttpHeaderPrefix, certificateChainLength, intermediateCerts, trustedRootCerts, isTruststoreLoaded);
    }

    @Override
    protected X509Certificate decodeCertificateFromPem(String pem) throws PemException {
        return CaddyProxySslClientCertificateLookupHelper.decodeCertificateFromHeaderValue(pem);
    }
}
