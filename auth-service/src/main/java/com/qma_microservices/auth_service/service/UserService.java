package com.qma_microservices.auth_service.service;

import com.qma_microservices.auth_service.dto.LoginDto;
import com.qma_microservices.auth_service.dto.SignupDto;
import com.qma_microservices.auth_service.dto.UserDto;

public interface UserService {
    public UserDto createUser(SignupDto signupDto);

    public UserDto getUserById(Long id);

    String login(LoginDto loginDto);
}
