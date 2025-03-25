package com.jack.jwtsecurity.user;


import com.jack.jwtsecurity.auth.UserLogin;
import com.jack.jwtsecurity.user.exception.UserNotFoundException;
import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.NotFoundException;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserService {

    @Inject
    RoleService roleService;

    @Inject
    UserRepository userRepository;

    // Get all users
    public List<User> getAllUsers(int page, int size) {
//        return User.list("active", true);

        return userRepository.find("enabled", true).page(page, size).list();
    }

    // Get user by ID
    public Optional<User> getUserById(Long id) {
        User user = User.findById(id);
        return Optional.ofNullable(user.enabled ? user : null);
    }

    public User getUserByEmail(String email) {
        return User.find("email", email).firstResult();
    }

    public User validateUserByLogin(UserLogin login) {
        User user = User.find("email", login.email()).firstResult();

        if (user == null || !user.enabled ) {
            throw new NotFoundException("User not found");
        }
        if(!BcryptUtil.matches(login.password(), user.password)) {

            throw new NotFoundException("Invalid password");
        }
        return user;
    }

    // Create a new user
    @Transactional
    public User createUser(UserDto userDto) {
        System.out.println("create resource - "+ userDto);
        User user = new User(); // Convert UserDto to User entity
        user.login = userDto.login();
        user.email = userDto.email();
        user.password = BcryptUtil.bcryptHash(userDto.password());
        user.roles = Role.find("id in ?1", userDto.roleIds()).list();
        user.persist();
        return user;
    }

    // Update an existing user
    @Transactional
    public User updateUser(Long id, UserDto userDto) {
        User user = User.findById(id);
        if (user == null || !user.enabled) {
            throw new UserNotFoundException("User not found, user is disabled");
        }
        user.login = userDto.login();
        user.email = userDto.email();
        user.password = BcryptUtil.bcryptHash(userDto.password());
        user.roles = Role.find("id in ?1", userDto.roleIds()).list();
        user.persist();
        return user;
    }

    // Delete a user
    @Transactional
    public void disableUser(Long id) {
        User user = User.findById(id);
        if (user == null || !user.enabled) {
            throw new UserNotFoundException("User not found, user is disabled");
        }
        user.enabled = false;
        user.persist();
    }

}