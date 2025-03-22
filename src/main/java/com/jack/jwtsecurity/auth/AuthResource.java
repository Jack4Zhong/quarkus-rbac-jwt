package com.jack.jwtsecurity.auth;


import com.jack.jwtsecurity.token.TokenResponse;
import com.jack.jwtsecurity.token.TokenService;
import com.jack.jwtsecurity.user.RoleService;
import com.jack.jwtsecurity.user.User;
import com.jack.jwtsecurity.user.UserDto;
import com.jack.jwtsecurity.user.UserService;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logmanager.Logger;

import java.io.IOException;



@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    public final static Logger LOGGER = Logger.getLogger(AuthResource.class.getSimpleName());

    @Inject
    UserService userService;

    @Inject
    RoleService roleService;

    @Inject
    AuthService authService;

    @Inject
    TokenService tokenService;

    final static String BEARER_TOKEN_PREFIX = "Bearer ";


    @POST
    @Path("/register")
    @Transactional
    public Response register(UserDto userDto) {
        User existingUser = userService.getUserByEmail(userDto.email());
        if (existingUser != null) {
            return Response.status(Response.Status.CONFLICT).build();
        }
        User newUser = userService.createUser(userDto);
        System.out.println("User created");
        return Response.status(Response.Status.CREATED).entity(newUser).build();
    }

    @POST
    @Path("/login")
    public Response login(UserLogin login) {
//        User existingUser = User.find("email", login.email()).firstResult();
        User existingUser = userService.validateUserByLogin(login);
        if (existingUser == null) {
//            throw new WebApplicationException(Response.status(404).entity("No user found or password is incorrect").build());
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        String accessToken = authService.generateAccessToken(existingUser.email, existingUser.password, roleService.rolesToList(existingUser.roles));

        tokenService.revokeAllUserTokens(existingUser);
        tokenService.saveToken(accessToken, existingUser);

        String refreshToken = authService.generateRefreshToken(existingUser.email, existingUser.password);

        return Response.ok(new TokenResponse(accessToken,refreshToken)).build();
    }


    @POST
    @Path("/refresh-token")
    public Response refreshToken( @HeaderParam("Authorization") String authHeader) throws IOException {

        if (authHeader == null || !authHeader.startsWith(BEARER_TOKEN_PREFIX)) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        String refreshToken = authHeader.substring(BEARER_TOKEN_PREFIX.length());
        User validatedUser = authService.validateRefreshToken(refreshToken);
        if (validatedUser == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        String accessToken = authService.generateAccessToken(validatedUser.email, validatedUser.password, roleService.rolesToList(validatedUser.roles));
        return Response.ok(new TokenResponse(accessToken,refreshToken)).build();
    }

    @POST
    @Path("/logout")
    public Response logout(@HeaderParam("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith(BEARER_TOKEN_PREFIX)) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        String accessToken = authHeader.substring(BEARER_TOKEN_PREFIX.length());
        authService.logout(accessToken);
        return Response.noContent().build();
    }
}
