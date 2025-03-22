package com.jack.jwtsecurity.user;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "roles")
public class Role extends PanacheEntity {

    @Column(unique = true, nullable = false)
    public String name;

    public String description;

    @ManyToMany(mappedBy = "roles", fetch = FetchType.LAZY)
    @JsonIgnore
    public List<User> users;

    public boolean enabled= true;

}
