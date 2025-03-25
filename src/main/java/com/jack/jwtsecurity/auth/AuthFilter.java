package com.jack.jwtsecurity.auth;

import com.jack.jwtsecurity.token.TokenService;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logmanager.Logger;


@Provider
public class AuthFilter implements ContainerRequestFilter {

    public final static Logger LOGGER = Logger.getLogger(AuthFilter.class.getSimpleName());

    @Inject
    TokenService tokenService;

    @Inject
    AuthService authService;

    @Context
    SecurityContext securityContext;

    final static String BEARER_TOKEN_PREFIX = "Bearer ";

    @Override
    public void filter(ContainerRequestContext requestContext) {
        LOGGER.info("Filter for AccessToken");
//        LOGGER.info("Request URI: " + requestContext.getUriInfo().getRequestUri().getPath());
//        String path = requestContext.getUriInfo().getRequestUri().getPath();
        /* Skip the refresh token*/
//        if (path.equals("/auth/refresh-token")) return;

        String authHeader = requestContext.getHeaderString("Authorization");
        if (authHeader != null && authHeader.startsWith(BEARER_TOKEN_PREFIX)) {
            String bearerToken = tokenService.getBearerToken(authHeader);

            String email = authService.getEmailFromToken(bearerToken);
            if (email == null || !email.equals(securityContext.getUserPrincipal().getName())) {
                Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Unauthorized: login email not match Token emal")
                        .build();
            }

            tokenService.findToken(bearerToken);
            LOGGER.info("Found access token: " + bearerToken);
        }


    }
}
