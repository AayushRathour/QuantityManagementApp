package com.qma_microservices.auth_service.service.impl;

import com.qma_microservices.auth_service.dto.LoginDto;
import com.qma_microservices.auth_service.dto.SignupDto;
import com.qma_microservices.auth_service.dto.UserDto;
import com.qma_microservices.auth_service.entity.User;
import com.qma_microservices.auth_service.exception.UserNotFoundException;
import com.qma_microservices.auth_service.mapper.Mapper;
import com.qma_microservices.auth_service.repository.UserRepo;
import com.qma_microservices.auth_service.service.JWTService;
import com.qma_microservices.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepo userRepo;
    private final Mapper<SignupDto, User> signupRequestMapper;
    private final Mapper<User, UserDto> userResponseMapper;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    @Override
    public UserDto createUser(SignupDto signupDto) {
        User user = signupRequestMapper.mapTo(signupDto);
        user.setPassword(passwordEncoder.encode(signupDto.getPassword()));

        User savedUser = userRepo.save(user);
        return userResponseMapper.mapTo(savedUser);
    }

    @Override
    public UserDto getUserById(Long id) {
        User user = userRepo.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User with user id " + id + " does not exist!"));
        return userResponseMapper.mapTo(user);
    }

    @Override
    public String login(LoginDto loginDto) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword()));
        return jwtService.generateToken(authentication.getName());
    }
}
