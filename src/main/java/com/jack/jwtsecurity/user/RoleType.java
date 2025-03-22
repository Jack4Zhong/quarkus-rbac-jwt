package com.jack.jwtsecurity.user;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RoleType {

    private RoleType() { }
    public static final String USER = "User";
    public static final String MANAGER = "Manager";
    public static final String ADMIN = "Admin";


    public static Set<String> getAllRoleTypes() {
        return Set.of(USER, MANAGER, ADMIN);
    }
}
