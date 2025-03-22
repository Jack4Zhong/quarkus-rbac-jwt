package com.jack.jwtsecurity.auth;

import jakarta.validation.constraints.NotEmpty;

public record UserLogin(
        @NotEmpty (message = "email is required")
        String email,
        @NotEmpty (message = "Password is required")
        String password
) {
}
