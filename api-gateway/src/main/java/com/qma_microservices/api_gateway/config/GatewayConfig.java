package com.qma_microservices.api_gateway.config;

import com.qma_microservices.api_gateway.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

//@Configuration
//@RequiredArgsConstructor
//public class GatewayConfig {
//
//    private final JwtAuthenticationFilter jwtFilter;
//
//    @Bean
//    public RouteLocator routes(RouteLocatorBuilder builder) {
//        return builder.routes()
//
//                // Public — no filter
//                .route("auth-service", r -> r
//                        .path("/api/v1/auth/**")
//                        .uri("lb://auth-service"))
//
//                // Protected — JWT filter applied
//                .route("quantity-service", r -> r
//                        .path("/api/v1/quantities/**")
//                        .filters(f -> f.filter(jwtFilter.apply(new JwtAuthenticationFilter.Config())))
//                        .uri("lb://quantity-service"))
//
//                .build();
//    }
//}
//
