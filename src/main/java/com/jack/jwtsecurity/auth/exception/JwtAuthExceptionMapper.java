package com.jack.jwtsecurity.auth.exception;


import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class JwtAuthExceptionMapper implements ExceptionMapper<JwtAuthException> {
    @Override
    public Response toResponse(JwtAuthException e) {
        return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
    }
}
