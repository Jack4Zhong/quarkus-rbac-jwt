package com.jack.jwtsecurity.auth;


import com.jack.jwtsecurity.auth.exception.JwtAuthException;
import com.jack.jwtsecurity.token.Token;
import com.jack.jwtsecurity.token.TokenService;
import com.jack.jwtsecurity.token.exception.TokenNotFoundException;
import com.jack.jwtsecurity.user.User;
import com.jack.jwtsecurity.user.UserService;
import com.jack.jwtsecurity.user.exception.UserNotFoundException;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logmanager.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RequestScoped
public class AuthService {

    public final static Logger LOGGER = Logger.getLogger(AuthService.class.getSimpleName());


    @Inject
    AuthUtils authUtils;

    @Inject
    TokenService tokenService;

    @Inject
    SecurityIdentity securityIdentity;


    @ConfigProperty(name = "quarkus.smallrye-jwt.token.expiration")
    float ACCESS_TOKEN_EXPIRE_TIME;

    @ConfigProperty(name = "quarkus.smallrye-jwt.token.refresh-expiration")
    float REFRESH_TOKEN_EXPIRE_TIME;

    @ConfigProperty(name = "quarkus.smallrye-jwt.token.issuer")
    String issuer;

    final String BEARER_TOKEN_PREFIX = "Bearer ";
    @Inject
    UserService userService;
    @Inject
    SecurityContext securityContext;


    public String getEmailFromToken(String token) {
        String email = null;
        try {
            JwtClaims claims = authUtils.parseToken(token);

            Map<String, Object> claimsMap = claims.getClaimsMap();
            email = (String) claimsMap.get("sub");
        } catch ( InvalidJwtException | NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new JwtAuthException(e.getMessage());
        }
        return email;
    }

    public User validateRefreshToken(String refreshToken) {
        LOGGER.info("Refresh token: " + refreshToken);
        User user = new User();
        try {
            JwtClaims claims = authUtils.parseToken(refreshToken);

//            for (Map.Entry<String, Object> entry : claims.getClaimsMap().entrySet()) {
//                LOGGER.info("\t claim: %s, value: %s\n".formatted(entry.getKey(), entry.getValue()));
//            }

            Map<String, Object> claimsMap = claims.getClaimsMap();
            String email = (String) claimsMap.get("sub");
            LOGGER.info("email: " + email);
            // Parse the extracted numeric value to a long
            long expiredSeconds = (long) claimsMap.get("exp"); // Use numericValue here, not authTimeString
            LOGGER.info("authTimeSeconds: " + expiredSeconds);
            // Convert to NumericDate
            NumericDate expirationDate = NumericDate.fromSeconds(expiredSeconds);

            user = userService.getUserByEmail(email);

            if (user == null) {
                throw new UserNotFoundException("The user does not exist");
            }

            if (expirationDate.isBefore(NumericDate.now())) {
                throw new TokenNotFoundException("The token expired");
            }

        } catch (Exception e) {
            throw new JwtAuthException(e.getMessage());
        }

        return user;
    }

    @Transactional
    public void logout(String accessToken) {

        Token existingToken = tokenService.findToken(accessToken);
        User user = existingToken.user;
        tokenService.revokeAllUserTokens(user);
    }

    public String generateAccessToken(String subject, String name, List<String> roles) {
        try {
            JwtClaims jwtClaims = new JwtClaims();
            jwtClaims.setIssuer(issuer); // change to your company
            jwtClaims.setJwtId(UUID.randomUUID().toString());
            jwtClaims.setSubject(subject);
            jwtClaims.setClaim(Claims.upn.name(), subject);
            jwtClaims.setClaim(Claims.preferred_username.name(), name); //add more
            jwtClaims.setClaim(Claims.groups.name(), roles);
//            jwtClaims.setAudience("using-jwt");
            jwtClaims.setExpirationTimeMinutesInTheFuture(ACCESS_TOKEN_EXPIRE_TIME / 60); // Access Token

            String token = authUtils.generateTokenString(jwtClaims);
            LOGGER.info("ACCESS TOKEN generated: " + token);
            return token;
        } catch (Exception e) {
//            e.printStackTrace();
            throw new JwtAuthException(e.getMessage());
        }
    }


    public String generateRefreshToken(String subject, String name) {
        try {
            JwtClaims jwtClaims = new JwtClaims();
            jwtClaims.setIssuer(issuer); // change to your company
            jwtClaims.setJwtId(UUID.randomUUID().toString());
            jwtClaims.setSubject(subject);
            jwtClaims.setClaim(Claims.upn.name(), subject);
            jwtClaims.setClaim(Claims.preferred_username.name(), name); //add more
//            jwtClaims.setClaim(Claims.groups.name(), roles);
//            jwtClaims.setAudience("using-jwt");
            jwtClaims.setExpirationTimeMinutesInTheFuture(REFRESH_TOKEN_EXPIRE_TIME / 60); // Access Token

            String token = authUtils.generateTokenString(jwtClaims);
            LOGGER.info("REFRESH TOKEN generated: " + token);
            return token;
        } catch (Exception e) {
//            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
