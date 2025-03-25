package com.jack.jwtsecurity.auth;

import com.jack.jwtsecurity.token.TokenResponse;
import com.jack.jwtsecurity.token.TokenService;
import com.jack.jwtsecurity.token.TokenSpec;
import com.jack.jwtsecurity.user.RoleService;
import com.jack.jwtsecurity.user.User;
import com.jack.jwtsecurity.user.UserDto;
import com.jack.jwtsecurity.user.UserService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
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
            return Response.status(Response.Status.CONFLICT).entity("This Email has been existed in system").build();
        }
        User newUser = userService.createUser(userDto);
        return Response.status(Response.Status.CREATED).entity(newUser).build();
    }

    @POST
    @Path("/login")
    public Response login(UserLogin login) {
//        User existingUser = User.find("email", login.email()).firstResult();
        User existingUser = userService.validateUserByLogin(login);
        if (existingUser == null) {
//            throw new WebApplicationException(Response.status(404).entity("No user found or password is incorrect").build());
            return Response.status(Response.Status.UNAUTHORIZED).entity("User is not existed in the system").build();
        }

        String accessToken = authService.generateAccessToken(existingUser.email, existingUser.password, roleService.rolesToList(existingUser.roles));

        tokenService.revokeAllUserTokens(existingUser);
        tokenService.saveToken(accessToken, existingUser, TokenSpec.ACCESS_TOKEN);

        String refreshToken = authService.generateRefreshToken(existingUser.email, existingUser.password);
        tokenService.saveToken(refreshToken, existingUser, TokenSpec.REFRESH_TOKEN);

        return Response.ok(new TokenResponse(accessToken,refreshToken)).build();
    }


    @POST
    @Path("/refresh-token")
    public Response refreshToken( @HeaderParam("Authorization") String authHeader) throws IOException {

        String refreshToken = tokenService.getBearerToken(authHeader);

        User validatedUser = authService.validateRefreshToken(refreshToken);
        if (validatedUser == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Refresh Token has been expired, please login again").build();
        }
        String accessToken = authService.generateAccessToken(validatedUser.email, validatedUser.password, roleService.rolesToList(validatedUser.roles));
        tokenService.saveToken(accessToken, validatedUser, TokenSpec.ACCESS_TOKEN);

        return Response.ok(new TokenResponse(accessToken,refreshToken)).build();

    }

    @POST
    @Path("/logout")
    public Response logout(@HeaderParam("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith(BEARER_TOKEN_PREFIX)) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        String accessToken = tokenService.getBearerToken(authHeader);
        authService.logout(accessToken);
        return Response.noContent().entity("User logout").build();
    }

}
