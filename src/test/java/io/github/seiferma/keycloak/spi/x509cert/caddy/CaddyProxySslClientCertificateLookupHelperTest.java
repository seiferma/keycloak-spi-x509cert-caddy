package io.github.seiferma.keycloak.spi.x509cert.caddy;

import org.apache.commons.codec.Charsets;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CaddyProxySslClientCertificateLookupHelperTest {

    @BeforeAll
    public static void init() {
        CryptoIntegration.init(CaddyProxySslClientCertificateLookupHelperTest.class.getClassLoader());
    }

    @Test
    public void testCorrectParsingOfClientCertHeaderValueWithColons() throws IOException {
        String clientCertHeaderValue = loadCertExample();

        X509Certificate parsedCert = CaddyProxySslClientCertificateLookupHelper.decodeCertificateFromHeaderValue(clientCertHeaderValue);

        assertNotNull(parsedCert);
    }

    @Test
    public void testCorrectParsingOfClientCertHeaderValueWithoutColons() throws IOException {
        String clientCertHeaderValue = loadCertExample();
        clientCertHeaderValue = clientCertHeaderValue.substring(1, clientCertHeaderValue.length() - 1);

        X509Certificate parsedCert = CaddyProxySslClientCertificateLookupHelper.decodeCertificateFromHeaderValue(clientCertHeaderValue);

        assertNotNull(parsedCert);
    }

    private String loadCertExample() throws IOException {
        URL uri = this.getClass().getResource("header_value_client_cert");
        return IOUtils.toString(uri, Charsets.UTF_8);
    }

}
