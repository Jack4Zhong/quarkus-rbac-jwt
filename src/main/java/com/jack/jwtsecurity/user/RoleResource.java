package com.jack.jwtsecurity.user;


import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;

import java.util.List;

@Path("/roles")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RoleResource {

    @Inject
    RoleService roleService;

    @GET
    public List<Role> getAllRoles() {
        return roleService.findAllRoles();
    }
}
