package com.qma_microservices.auth_service.controller;

import com.qma_microservices.auth_service.dto.LoginDto;
import com.qma_microservices.auth_service.dto.SignupDto;
import com.qma_microservices.auth_service.dto.UserDto;
import com.qma_microservices.auth_service.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@Slf4j
public class AuthController {
    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<UserDto> singup(@Valid @RequestBody SignupDto signupDto) {
        log.info("Sign up called");
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(signupDto));
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginDto loginDto, HttpServletResponse response) {
        log.info("Login called");
        String token = userService.login(loginDto);
        return ResponseEntity.accepted().body(token);
    }
}
