package com.qma_microservices.auth_service.mapper.impl;

import com.qma_microservices.auth_service.dto.UserDto;
import com.qma_microservices.auth_service.entity.User;
import com.qma_microservices.auth_service.mapper.Mapper;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserResponseMapper implements Mapper<User, UserDto> {
    private final ModelMapper modelMapper;
    @Override
    public UserDto mapTo(User user) {
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    public User mapFrom(UserDto userDto) {
        return modelMapper.map(userDto, User.class);
    }
}
