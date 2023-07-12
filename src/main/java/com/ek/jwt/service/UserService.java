package com.ek.jwt.service;

import com.ek.jwt.controller.dto.UserInput;
import com.ek.jwt.controller.dto.UserResult;
import com.ek.jwt.model.Role;
import com.ek.jwt.model.User;
import com.ek.jwt.repository.UserRepository;
import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserResult register(UserInput userInput) {

        if (this.userRepository.findByUsername(userInput.username()).isPresent()) {
            throw new ValidationException("Username exists!");
        }

        if (!userInput.password().equals(userInput.repeatPassword())) {
            throw new ValidationException("Passwords don't match!");
        }

        var user = User.builder()
                .username(userInput.username())
                .password(passwordEncoder.encode(userInput.password()))
                .roles(userInput.roles().stream()
                        .map(Role::valueOf)
                        .collect(Collectors.toSet()))
                .enabled(true)
                .build();

        user = this.userRepository.save(user);

        return new UserResult(user.getId(), user.getUsername(), null);
    }
}
