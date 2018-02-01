/*
 * This code is unpublished proprietary trade secret of
 * Visiona Sp. z o.o., ul. Życzkowskiego 14, 31-864 Kraków, Poland.
 *
 * This code is protected under Act on Copyright and Related Rights
 * and may be used only under the terms of license granted by
 * Visiona Sp. z o.o., ul. Życzkowskiego 14, 31-864 Kraków, Poland.
 *
 * Above notice must be preserved in all copies of this code.
 */

package com.github.mstawowiak.jose;

import java.security.KeyPair;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JwsRSATest {

    private static final int RSA_KEY_SIZE = 2048;

    private static final String HEADER_ALGORITHM = AlgorithmIdentifiers.RSA_USING_SHA512;
    private static final String KEY_ID = "a2jX73WZJ8LvLjhJ6MfzKdAKyKOlEp3P32athnX4";
    private static final String JOSE_TYPE = "JOSE";

    private KeyPair keyPair;

    @Before
    public void before() {
        keyPair = RSA.generateRSA(RSA_KEY_SIZE);
    }

    @Test
    public void shouldSignAndVerifyWithRSA() throws JoseException {
        String payload = "This is some text that is to be signed.";

        JsonWebSignature jwsForSign = buildJwsForSign(payload);
        String compactSerialization = jwsForSign.getCompactSerialization();
        JsonWebSignature jwsForVerify = buildJwsForVerify(compactSerialization);

        System.out.println("JWS compact serialization: " + compactSerialization);
        System.out.println("------------------------------------------------------------------");
        System.out.println("JWS for SIGN");
        System.out.println("HEADERS: " + jwsForSign.getHeaders().getFullHeaderAsJsonString());
        System.out.println("PAYLOAD: " + payload);
        System.out.println("------------------------------------------------------------------");
        System.out.println("JWS for VERIFY");
        System.out.println("HEADERS: " + jwsForVerify.getHeaders().getFullHeaderAsJsonString());
        System.out.println("PAYLOAD: " + jwsForVerify.getPayload());

        assertTrue(jwsForVerify.verifySignature());
        assertEquals(payload, jwsForVerify.getPayload());
        assertJweHeader(jwsForSign.getHeaders());
        assertJweHeader(jwsForVerify.getHeaders());
    }

    private JsonWebSignature buildJwsForSign(String payload) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(payload);
        jws.setAlgorithmHeaderValue(HEADER_ALGORITHM);
        jws.setKeyIdHeaderValue(KEY_ID);
        jws.setHeader(JoseHeaders.TYPE, JOSE_TYPE);
        jws.setKey(keyPair.getPrivate());

        return jws;
    }

    private JsonWebSignature buildJwsForVerify(String compactSerialization) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();

        jws.setAlgorithmConstraints(new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.WHITELIST, HEADER_ALGORITHM));

        jws.setCompactSerialization(compactSerialization);
        jws.setKey(keyPair.getPublic());

        return jws;
    }

    private static void assertJweHeader(Headers headers) {
        assertEquals(HEADER_ALGORITHM, headers.getStringHeaderValue(JoseHeaders.ALGORITHM));
        assertEquals(KEY_ID, headers.getStringHeaderValue(JoseHeaders.KEY_ID));
        assertEquals(JOSE_TYPE, headers.getStringHeaderValue(JoseHeaders.TYPE));
    }

}
