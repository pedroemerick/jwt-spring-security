package com.ek.jwt.controller;

import com.ek.jwt.controller.dto.AuthInput;
import com.ek.jwt.controller.dto.UserInput;
import com.ek.jwt.controller.dto.UserResult;
import com.ek.jwt.model.User;
import com.ek.jwt.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;

    @PostMapping("/register")
    public ResponseEntity<UserResult> register(@RequestBody @Valid UserInput userInput) {
        var user = this.userService.register(userInput);

        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<UserResult> login(@RequestBody @Valid AuthInput authInput) {
        try {
            var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authInput.username(), authInput.password())
            );

            var user = (User) authentication.getPrincipal();

            var now = Instant.now();
            var expiry = 3600L;

            var scope = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));

            var claims = JwtClaimsSet.builder()
                    .issuer("example.io")
                    .issuedAt(now)
                    .expiresAt(now.plusSeconds(expiry))
                    .subject(String.format("%s,%s", user.getId(), user.getUsername()))
                    .claim("roles", scope)
                    .build();

            var jwsHeader = JwsHeader.with(() -> "HS256").build();
            var token = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims))
                    .getTokenValue();

            var userResult = new UserResult(user.getId(), user.getUsername(), null);

            return ResponseEntity.ok()
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .body(userResult);
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
