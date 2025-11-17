package com.raisehigh.saas.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.raisehigh.saas.auth.domain.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {
    private String id;
    private String email;
    private String fullName;
    private Role role;
    private Boolean emailVerified;
    private LocalDateTime createdAt;
}