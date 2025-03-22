package com.jack.jwtsecurity.user;

import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record UserDto(
        @NotEmpty( message = "Login is required")
        String login,
        @NotEmpty( message = "Email is required")
        String email,
        @NotEmpty( message = "Password is required")
        String password,
        Set<Long> roleIds
) {
    // If no roles is provided, default to USER
    public UserDto {
        if (roleIds == null || roleIds.isEmpty()) {
            roleIds.add(1l);
        }
    }
}
