package com.jack.jwtsecurity.user;


import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;

@Path("/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource {

    @Inject
    UserService service;

    @GET
    public List<User> getAllUsers(@QueryParam("page") int page, @QueryParam("size") int size) {
        return service.getAllUsers(page, size);
    }

    @GET
    @Path("/{id}")
    public Response getUserById(@PathParam("id") Long id) {
        User existingUser =  service.getUserById(id);
        return Response.ok(existingUser).build();
    }

    @POST
    @Transactional
    public Response createUser(UserDto userDto) {

        User user = service.createUser(userDto);
        return Response.status(Response.Status.CREATED).entity(user).build();
    }

    @PUT
    @Path("/{id}")
    @Transactional
    public Response updateUser(@PathParam("id") Long id, UserDto userDto) {

        User user;
        try {
            user = service.updateUser(id, userDto);
        } catch (NotFoundException ex){
            return Response.status(Response.Status.NOT_FOUND).build();
        }
//        return Response.status(Response.Status.NO_CONTENT).build();
        return Response.ok(user).build();
    }

    @DELETE
    @Path("/{id}")
    @Transactional
    public Response deleteUser(@PathParam("id") Long id) {

        try {
            service.disableUser(id);
        } catch (NotFoundException ex){
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.noContent().build();
    }


}
