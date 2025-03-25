package com.jack.jwtsecurity.user;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.jack.jwtsecurity.token.Token;
import com.jack.jwtsecurity.core.BaseEntity;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "`users`")
public class User extends BaseEntity {

    public String login;
    @Column(unique = true, nullable = false)
    public String email;

    @JsonIgnore
    public String password;

    public boolean enabled= true;

    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )

    public List<Role> roles;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonIgnore
    public List<Token> tokens;


}
