package com.github.mstawowiak.jose;

import java.util.Arrays;
import java.util.List;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;

public class JwtTest {

    private static final int RSA_KEY_SIZE = 2048;

    private static final String HEADER_ALGORITHM = AlgorithmIdentifiers.RSA_USING_SHA256;
    private static final String KEY_ID = "a2jX73WZJ8LvLjhJ6MfzKdAKyKOlEp3P32athnX4";
    private static final String JOSE_TYPE = "JOSE";

    private RsaJsonWebKey rsaJsonWebKey;

    @Before
    public void before() throws JoseException {
        rsaJsonWebKey = RsaJwkGenerator.generateJwk(RSA_KEY_SIZE);
        rsaJsonWebKey.setKeyId(KEY_ID);
    }

    @Test
    public void shouldCreateAndConsumeJwt() throws JoseException, MalformedClaimException {
        JwtClaims claims = buildJwtClaims();
        JsonWebSignature jws = buildJwsForSign(claims.toJson());

        String jwt = jws.getCompactSerialization();
        System.out.println("JWT: " + jwt);

        JwtConsumer jwtConsumer = buildJwtConsumer();

        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            System.out.println("JWT valid! " + jwtClaims);
        } catch (InvalidJwtException e) {
            System.out.println("JWT invalid! " + e);
        }
    }

    private JwtClaims buildJwtClaims() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("matti");
        claims.setAudience("github");
        claims.setExpirationTimeMinutesInTheFuture(15);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(3);
        claims.setSubject("JWT test");
        claims.setClaim("email", "mail@github.com");
        List<String> groups = Arrays.asList("snowboarders", "freeriders");
        claims.setStringListClaim("groups", groups);

        return claims;
    }

    private JwtConsumer buildJwtConsumer() {
        return new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer("matti")
                .setExpectedAudience("github")
                .setVerificationKey(rsaJsonWebKey.getKey())
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.WHITELIST, HEADER_ALGORITHM))
                .build();
    }

    private JsonWebSignature buildJwsForSign(String payload) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();

        jws.setPayload(payload);
        jws.setAlgorithmHeaderValue(HEADER_ALGORITHM);
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setHeader(JoseHeaders.TYPE, JOSE_TYPE);
        jws.setKey(rsaJsonWebKey.getPrivateKey());

        return jws;
    }

}
