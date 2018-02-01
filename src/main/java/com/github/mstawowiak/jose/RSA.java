package com.github.mstawowiak.jose;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public final class RSA {

    public static final String RSA = "RSA";

    public static KeyPair generateRSA(int rsaKeySize) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
            keyGen.initialize(rsaKeySize);

            return keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Required cryptographic algorithm '" + RSA + "' is not supported", ex);
        }
    }

    private RSA() {
    }

}
