package com.raisehigh.saas.auth.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @JsonIgnore
    @Column(nullable = false)
    private String password;

    private String fullName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    // ------------------------
    // SaaS-specific fields
    // ------------------------

    @Column(nullable = false)
    private Boolean enabled = true;                    // Account is active

    @Column(nullable = false)
    private Boolean emailVerified = false;             // Email verification status

    @Column(nullable = false)
    private Boolean accountNonLocked = true;           // Lock status

    private LocalDateTime createdAt;                   // User registration timestamp

    private LocalDateTime lastLoginAt;

    private LocalDateTime deletedAt;                     // Soft-delete timestamp


    // Auto-set createdAt timestamp
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }


    // ------------------------
    // UserDetails Interface
    // ------------------------

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of((GrantedAuthority) () -> role.name());
    }

    @Override
    @JsonIgnore
    public String getUsername() {
        return email;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return enabled;
    }
}
