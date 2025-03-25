package com.jack.jwtsecurity.token.exception;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class TokenNotFoundExceptionMapper implements ExceptionMapper<TokenNotFoundException> {

    @Override
    public Response toResponse(TokenNotFoundException e) {
        return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
    }
}
