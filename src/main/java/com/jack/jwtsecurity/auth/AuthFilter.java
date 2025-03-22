package com.jack.jwtsecurity.auth;

import com.jack.jwtsecurity.token.Token;
import com.jack.jwtsecurity.token.TokenService;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import org.jose4j.jwt.consumer.JwtContext;

import java.io.IOException;

public class AuthFilter implements ContainerRequestFilter {

    @Inject
    TokenService tokenService;

    final static String BEARER_TOKEN_PREFIX = "Bearer ";

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        String tokenType = requestContext.getHeaderString("TokenType");
        if (tokenType != null && tokenType.equals("AccessToken")) {
            String authHeader = requestContext.getHeaderString("Authorization");

            if (authHeader != null && authHeader.startsWith(BEARER_TOKEN_PREFIX)) {
                String accessToken = authHeader.substring(BEARER_TOKEN_PREFIX.length());
                Token token = tokenService.findToken(accessToken);

                if (token == null || token.revoked || token.expired) {
                    Response.status(Response.Status.UNAUTHORIZED)
                            .entity("Unauthorized: Missing or invalid Authorization header")
                            .build();
                }
            }
        }
    }
}
