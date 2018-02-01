package com.github.mstawowiak.jose;

public final class JoseHeaders {

    /**
     * JOSE {@code Algorithm} header parameter name: <code>"alg"</code>
     */
    public static final String ALGORITHM = "alg";

    /**
     * JOSE {@code Encryption Algorithm} header parameter name: <code>"enc"</code>
     */
    public static final String ENCRYPTION_ALGORITHM = "enc";

    /**
     * JOSE {@code Key ID} header parameter name: <code>"kid"</code>
     */
    public static final String KEY_ID = "kid";

    /**
     * JOSE {@code Type} header parameter name: <code>"typ"</code>
     */
    public static final String TYPE = "typ";

    /**
     * JOSE {@code Content Type} header parameter name: <code>"cty"</code>
     */
    public static final String CONTENT_TYPE = "cty";

    private JoseHeaders() {
    }
}
