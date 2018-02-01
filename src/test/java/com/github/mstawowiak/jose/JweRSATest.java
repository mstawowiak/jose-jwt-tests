package com.github.mstawowiak.jose;

import java.security.KeyPair;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class JweRSATest {

    private static final int RSA_KEY_SIZE = 2048;

    private static final String HEADER_ALGORITHM = KeyManagementAlgorithmIdentifiers.RSA_OAEP;
    private static final String CONTENT_ENCRYPTION_ALGORITHM = ContentEncryptionAlgorithmIdentifiers.AES_128_GCM;
    private static final String KEY_ID = "a2jX73WZJ8LvLjhJ6MfzKdAKyKOlEp3P32athnX4";
    private static final String JOSE_TYPE = "JOSE";

    private KeyPair keyPair;

    @Before
    public void before() {
        keyPair = RSA.generateRSA(RSA_KEY_SIZE);
    }

    @Test
    public void shouldEncryptAndDecryptWithRSA() throws JoseException {
        String plaintext = "Some text that is encrypted.";

        JsonWebEncryption jweForEncrypt = buildJweForEncrypt(plaintext);
        String compactSerialization = jweForEncrypt.getCompactSerialization();
        JsonWebEncryption jweForDecrypt = buildJweForDecrypt(compactSerialization);

        System.out.println("JWE compact serialization: " + compactSerialization);
        System.out.println("------------------------------------------------------------------");
        System.out.println("JWE for ENCRYPT");
        System.out.println("HEADERS: " + jweForEncrypt.getHeaders().getFullHeaderAsJsonString());
        System.out.println("PLAINTEXT: " + plaintext);
        System.out.println("------------------------------------------------------------------");
        System.out.println("JWE for DECRYPT");
        System.out.println("HEADERS: " + jweForDecrypt.getHeaders().getFullHeaderAsJsonString());
        System.out.println("DECRYPTED: " + jweForDecrypt.getPlaintextString());

        assertEquals(plaintext, jweForDecrypt.getPlaintextString());
        assertJweHeader(jweForEncrypt.getHeaders());
        assertJweHeader(jweForDecrypt.getHeaders());
    }

    private static void assertJweHeader(Headers headers) {
        assertEquals(HEADER_ALGORITHM, headers.getStringHeaderValue(JoseHeaders.ALGORITHM));
        assertEquals(CONTENT_ENCRYPTION_ALGORITHM, headers.getStringHeaderValue(JoseHeaders.ENCRYPTION_ALGORITHM));
        assertEquals(KEY_ID, headers.getStringHeaderValue(JoseHeaders.KEY_ID));
        assertEquals(JOSE_TYPE, headers.getStringHeaderValue(JoseHeaders.TYPE));
        assertEquals(HEADER_ALGORITHM, headers.getStringHeaderValue(JoseHeaders.ALGORITHM));
    }

    private JsonWebEncryption buildJweForEncrypt(String plaintext) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();

        jwe.setPlaintext(plaintext);
        jwe.setAlgorithmHeaderValue(HEADER_ALGORITHM);
        jwe.setEncryptionMethodHeaderParameter(CONTENT_ENCRYPTION_ALGORITHM);
        jwe.setKeyIdHeaderValue(KEY_ID);
        jwe.setHeader(JoseHeaders.TYPE, JOSE_TYPE);
        jwe.setKey(keyPair.getPublic());

        return jwe;
    }

    private JsonWebEncryption buildJweForDecrypt(String compactSerialization) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();

        jwe.setAlgorithmConstraints(new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.WHITELIST, HEADER_ALGORITHM));
        jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.WHITELIST, CONTENT_ENCRYPTION_ALGORITHM));

        jwe.setCompactSerialization(compactSerialization);
        jwe.setKey(keyPair.getPrivate());

        return jwe;
    }

}
