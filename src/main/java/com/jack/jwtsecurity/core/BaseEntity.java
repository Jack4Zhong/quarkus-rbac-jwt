package com.jack.jwtsecurity.core;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

import java.time.LocalDate;
import java.time.LocalDateTime;

@MappedSuperclass
public abstract class BaseEntity extends PanacheEntity {
    public LocalDateTime createdAt;
    public LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}