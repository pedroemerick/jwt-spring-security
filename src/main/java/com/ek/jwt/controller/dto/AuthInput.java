package com.ek.jwt.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

public record AuthInput (
        @NotNull @Email String username,
        @NotNull String password) {

}
