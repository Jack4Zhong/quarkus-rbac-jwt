package com.jack.jwtsecurity.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.jack.jwtsecurity.core.BaseEntity;
import com.jack.jwtsecurity.user.User;
import jakarta.persistence.*;


@Entity
@Table(name = "tokens")
public class Token extends BaseEntity {

    @Column(unique = true, nullable = false, length = 1000)
    public String token;

    @Enumerated(EnumType.STRING)
    public TokenType tokenType = TokenType.BEARER;

    @Enumerated(EnumType.STRING)
    public TokenSpec tokenSpec;

    public boolean revoked = false;

//    public boolean expired = false;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @JsonIgnore
    public User user;
}
