package com.jack.jwtsecurity.auth;

import com.jack.jwtsecurity.user.User;
import io.smallrye.jwt.util.KeyUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Singleton;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logmanager.Logger;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@Singleton
public class AuthUtils {

    public final static Logger LOGGER = Logger.getLogger(AuthUtils.class.getSimpleName());

    @ConfigProperty(name = "smallrye.jwt.sign.key.location")
    String privateKeyLocation;

    @ConfigProperty(name = "mp.jwt.verify.publickey.location")
    String publicKeyLocation;

    public JwtClaims parseToken(String token) throws InvalidJwtException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = readPublicKey("/"+publicKeyLocation);

        LOGGER.info("publicKey: " + publicKey);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(publicKey)
                .setRequireIssuedAt()
                .setExpectedType(true, "JWT")
                .setSkipDefaultAudienceValidation()
                .build();

        JwtContext jwtContext = jwtConsumer.process(token);
        return jwtContext.getJwtClaims();
    }


    public PublicKey readPublicKey(final String pemResName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream is = AuthUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = is.read(tmp);
        return decodePublicKey(new String(tmp, 0, length, StandardCharsets.UTF_8));
    }

    public PublicKey decodePublicKey(final String pemEncoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }



    public  String generateTokenString(JwtClaims claims) throws Exception {
        // Use the private key associated with the public key for a valid signature
        PrivateKey pk = readPrivateKey("/"+privateKeyLocation);

        return generateTokenString(pk, "/"+privateKeyLocation, claims);
    }

    private  String generateTokenString(PrivateKey privateKey, String kid, JwtClaims claims) throws Exception {

        long currentTimeInSecs = currentTimeInSecs();

        claims.setIssuedAt(NumericDate.fromSeconds(currentTimeInSecs));
        claims.setClaim(Claims.auth_time.name(), NumericDate.fromSeconds(currentTimeInSecs));

        for (Map.Entry<String, Object> entry : claims.getClaimsMap().entrySet()) {
            LOGGER.info("\tAdded claim: %s, value: %s\n".formatted(entry.getKey(), entry.getValue()));
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(privateKey);
        jws.setKeyIdHeaderValue(kid);
        jws.setHeader("typ", "JWT");
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        return jws.getCompactSerialization();
    }

    /**
     * Read a PEM encoded private key from the classpath
     *
     * @param pemResName - key file resource name
     * @return PrivateKey
     * @throws Exception on decode failure
     */
    public PrivateKey readPrivateKey(final String pemResName) throws Exception {
        InputStream is = AuthUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
//        assert contentIS != null;
        int length = is.read(tmp);
        return decodePrivateKey(new String(tmp, 0, length, StandardCharsets.UTF_8));
    }

    /**
     * Decode a PEM encoded private key string to an RSA PrivateKey
     *
     * @param pemEncoded - PEM string for private key
     * @return PrivateKey
     * @throws Exception on decode failure
     */
    public  PrivateKey decodePrivateKey(final String pemEncoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    private  byte[] toEncodedBytes(final String pemEncoded) {
        final String normalizedPem = removeBeginEnd(pemEncoded);
        return Base64.getDecoder().decode(normalizedPem);
    }

    private  String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        pem = pem.replaceAll("-----END (.*)----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        return pem.trim();
    }

    /**
     * @return the current time in seconds since epoch
     */
    public int currentTimeInSecs() {
        long currentTimeMS = System.currentTimeMillis();
        return (int) (currentTimeMS / 1000);
    }
}
