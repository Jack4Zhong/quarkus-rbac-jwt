package com.jack.jwtsecurity.test;


import com.jack.jwtsecurity.user.RoleType;
import com.jack.jwtsecurity.user.User;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;


@Path("/test")
@Produces(MediaType.APPLICATION_JSON)
public class TestResource {


    @Context
    SecurityContext securityContext;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/hello")
    @PermitAll
    public String hello() {
        return "hello";
    }

    @GET
    @Path("/me")
    @RolesAllowed({RoleType.USER, RoleType.ADMIN})
    public User me() {
        return User.find("email", securityContext.getUserPrincipal().getName()).firstResult();
    }

    @GET
    @Path("/admin")
    @RolesAllowed(RoleType.ADMIN)
    public String adminTest() {
        return "If you see this text as a user, then something is broke";
    }

    @GET
    @Path("/void")
    @DenyAll
    public String nothing() {
        return "This method should always return 403";
    }

}
