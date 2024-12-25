package io.github.seiferma.keycloak.spi.x509cert.caddy;

import org.keycloak.common.util.Base64;
import org.keycloak.common.util.DerUtils;
import org.keycloak.common.util.PemException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

public interface CaddyProxySslClientCertificateLookupHelper {

    static X509Certificate decodeCertificateFromHeaderValue(String headerValue) throws PemException {
        String base64EncodedCertificate = parseBase64EncodedDerPayload(headerValue);
        byte[] derPayload = parseBinaryDerPayload(base64EncodedCertificate);
        return parseX509Certificate(derPayload);
    }

    private static String parseBase64EncodedDerPayload(String headerValue) {
        String trimmedHeaderValue = headerValue.trim();
        if (headerValue.matches("^:.+:$")) {
            return trimmedHeaderValue.substring(1, trimmedHeaderValue.length() - 1);
        }
        return trimmedHeaderValue;
    }
    private static byte[] parseBinaryDerPayload(String base64EncodedCertificate) {
        byte[] derCertificate;
        try {
            derCertificate = Base64.decode(base64EncodedCertificate);
        } catch (IOException e) {
            throw new PemException(e);
        }
        return derCertificate;
    }

    private static X509Certificate parseX509Certificate(byte[] derPayload) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(derPayload)) {
            return DerUtils.decodeCertificate(bis);
        } catch (Exception e) {
            throw new PemException(e);
        }
    }

}
