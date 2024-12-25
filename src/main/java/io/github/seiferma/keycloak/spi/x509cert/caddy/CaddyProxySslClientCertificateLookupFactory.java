package io.github.seiferma.keycloak.spi.x509cert.caddy;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.x509.NginxProxySslClientCertificateLookupFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.truststore.TruststoreProvider;
import org.keycloak.truststore.TruststoreProviderFactory;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class CaddyProxySslClientCertificateLookupFactory extends NginxProxySslClientCertificateLookupFactory {

    private static final Logger logger = Logger.getLogger(CaddyProxySslClientCertificateLookupFactory.class);
    private static final String PROVIDER = "caddy";
    private boolean isTruststoreLoaded = false;
    private final Set<X509Certificate> trustedRootCerts = ConcurrentHashMap.newKeySet();
    private final Set<X509Certificate> intermediateCerts = ConcurrentHashMap.newKeySet();

    @Override
    public String getId() {
        return PROVIDER;
    }

    @Override
    public X509ClientCertificateLookup create(KeycloakSession keycloakSession) {
        loadKeycloakTrustStore(keycloakSession);
        if (trustProxyVerification) {
            return new CaddyProxyTrustedClientCertificateLookup(sslClientCertHttpHeader,
                    sslChainHttpHeaderPrefix, certificateChainLength);
        } else {
            return new CaddyProxySslClientCertificateLookup(sslClientCertHttpHeader,
                    sslChainHttpHeaderPrefix, certificateChainLength, intermediateCerts, trustedRootCerts, isTruststoreLoaded);
        }
    }

    /**
     * Method copied because it is private in base class
     *
     * @see NginxProxySslClientCertificateLookupFactory#loadKeycloakTrustStore(KeycloakSession)
     */
    private void loadKeycloakTrustStore(KeycloakSession kcSession) {

        if (isTruststoreLoaded){
            return;
        }

        synchronized (this) {
            if (isTruststoreLoaded) {
                return;
            }
            logger.debug(" Loading Keycloak truststore ...");
            KeycloakSessionFactory factory = kcSession.getKeycloakSessionFactory();
            TruststoreProviderFactory truststoreFactory = (TruststoreProviderFactory) factory.getProviderFactory(TruststoreProvider.class, "file");
            TruststoreProvider provider = truststoreFactory.create(kcSession);

            if (provider != null && provider.getTruststore() != null) {
                trustedRootCerts.addAll(provider.getRootCertificates().values());
                intermediateCerts.addAll(provider.getIntermediateCertificates().values());
                logger.debugf("Keycloak truststore loaded for %s x509cert-lookup provider.", PROVIDER);

                isTruststoreLoaded = true;
            }
        }
    }
}
