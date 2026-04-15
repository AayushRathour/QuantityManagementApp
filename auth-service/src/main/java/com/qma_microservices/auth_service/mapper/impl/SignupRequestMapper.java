package com.qma_microservices.auth_service.mapper.impl;

import com.qma_microservices.auth_service.dto.SignupDto;
import com.qma_microservices.auth_service.entity.User;
import com.qma_microservices.auth_service.mapper.Mapper;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SignupRequestMapper implements Mapper<SignupDto, User> {
    private final ModelMapper modelMapper;
    @Override
    public User mapTo(SignupDto signupDto) {
        return modelMapper.map(signupDto, User.class);
    }

    @Override
    public SignupDto mapFrom(User user) {
        return modelMapper.map(user, SignupDto.class);
    }
}

