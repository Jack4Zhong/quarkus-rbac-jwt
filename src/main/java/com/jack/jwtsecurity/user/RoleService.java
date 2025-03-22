package com.jack.jwtsecurity.user;

import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@ApplicationScoped
public class RoleService {

    public boolean isValidRole(String roleName) {
        Set<String> roles = RoleType.getAllRoleTypes();
        return roles.contains(roleName);
    }

    public List<String> rolesToList(List<Role> roles) {
        return roles.stream().map(role -> role.name).collect(Collectors.toList());
    }

    public List<Role> findAllRoles() {
        return Role.list("enabled", true);
    }


}
