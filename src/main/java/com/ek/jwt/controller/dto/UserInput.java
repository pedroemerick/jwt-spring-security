package com.ek.jwt.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public record UserInput(
        @NotBlank @Email String username,
        @NotBlank String firstName,
        @NotBlank String lastName,
        @NotBlank String password,
        @NotBlank String repeatPassword,
        Set<String> roles) {

    public UserInput {
        if (Objects.isNull(roles)) {
            roles = new HashSet<>();
        }
    }
}
