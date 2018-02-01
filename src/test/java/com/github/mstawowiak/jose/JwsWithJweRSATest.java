package com.github.mstawowiak.jose;

import java.security.KeyPair;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JwsWithJweRSATest {

    private static final int RSA_KEY_SIZE = 2048;

    private static final String JWE_HEADER_ALGORITHM = KeyManagementAlgorithmIdentifiers.RSA_OAEP;
    private static final String JWS_HEADER_ALGORITHM = AlgorithmIdentifiers.RSA_USING_SHA512;

    private static final String CONTENT_ENCRYPTION_ALGORITHM = ContentEncryptionAlgorithmIdentifiers.AES_128_GCM;
    private static final String CONTENT_TYPE = "JWE";
    private static final String KEY_ID = "a2jX73WZJ8LvLjhJ6MfzKdAKyKOlEp3P32athnX4";
    private static final String JOSE_TYPE = "JOSE";

    private KeyPair producerKeyPair;
    private KeyPair consumerKeyPair;

    @Before
    public void before() {
        producerKeyPair = RSA.generateRSA(RSA_KEY_SIZE);
        consumerKeyPair = RSA.generateRSA(RSA_KEY_SIZE);
    }

    @Test
    public void shouldEncryptSignAndVerifyDecryptWithRSA() throws JoseException {
        String plaintext = "Some text that is encrypted and signed.";

        //Producer
        JsonWebEncryption jweForEncrypt = buildJweForEncrypt(plaintext);
        String jweCompactSerialization = jweForEncrypt.getCompactSerialization();

        JsonWebSignature jwsForSign = buildJwsForSign(jweCompactSerialization);
        String jwsCompactSerialization = jwsForSign.getCompactSerialization();

        //Consumer
        JsonWebSignature jwsForVerify = buildJwsForVerify(jwsCompactSerialization);
        JsonWebEncryption jweForDecrypt = buildJweForDecrypt(jwsForVerify.getPayload());

        System.out.println("PRODUCER:");
        System.out.println("JWE HEADERS: " + jweForEncrypt.getHeaders().getFullHeaderAsJsonString());
        System.out.println("JWS HEADERS: " + jwsForSign.getHeaders().getFullHeaderAsJsonString());
        System.out.println("PLAINTEXT: " + plaintext);

        System.out.println("------------------------------------------------------------------");
        System.out.println("CONSUMER:");
        System.out.println("JWE HEADERS: " + jweForDecrypt.getHeaders().getFullHeaderAsJsonString());
        System.out.println("JWS HEADERS: " + jwsForVerify.getHeaders().getFullHeaderAsJsonString());
        System.out.println("DECRYPTED: " + jweForDecrypt.getPlaintextString());

        assertTrue(jwsForVerify.verifySignature());
        assertEquals(jweCompactSerialization, jwsForVerify.getPayload());
        assertEquals(plaintext, jweForDecrypt.getPlaintextString());
    }

    private JsonWebEncryption buildJweForEncrypt(String plaintext) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();

        jwe.setPlaintext(plaintext);
        jwe.setAlgorithmHeaderValue(JWE_HEADER_ALGORITHM);
        jwe.setEncryptionMethodHeaderParameter(CONTENT_ENCRYPTION_ALGORITHM);
        jwe.setKeyIdHeaderValue(KEY_ID);
        jwe.setHeader(JoseHeaders.TYPE, JOSE_TYPE);
        jwe.setKey(consumerKeyPair.getPublic());

        return jwe;
    }

    private JsonWebSignature buildJwsForSign(String payload) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(payload);
        jws.setAlgorithmHeaderValue(JWS_HEADER_ALGORITHM);
        jws.setKeyIdHeaderValue(KEY_ID);
        jws.setContentTypeHeaderValue(CONTENT_TYPE);
        jws.setHeader(JoseHeaders.TYPE, JOSE_TYPE);
        jws.setKey(producerKeyPair.getPrivate());

        return jws;
    }

    private JsonWebSignature buildJwsForVerify(String compactSerialization) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();

        jws.setAlgorithmConstraints(new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.WHITELIST, JWS_HEADER_ALGORITHM));

        jws.setCompactSerialization(compactSerialization);
        jws.setKey(producerKeyPair.getPublic());

        return jws;
    }

    private JsonWebEncryption buildJweForDecrypt(String compactSerialization) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();

        jwe.setAlgorithmConstraints(new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.WHITELIST, JWE_HEADER_ALGORITHM));
        jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.WHITELIST, CONTENT_ENCRYPTION_ALGORITHM));

        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(consumerKeyPair.getPrivate());

        return jwe;
    }

}
