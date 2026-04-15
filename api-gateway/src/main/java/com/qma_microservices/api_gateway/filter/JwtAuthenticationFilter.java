package com.qma_microservices.api_gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
@Slf4j
public class JwtAuthenticationFilter
        extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Value("${security.jwt.secret}")
    private String jwtSecret;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);

            // 1. Check header presence
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Missing Authorization header");
                throw new RuntimeException("Header not found for token");
            }

            String token = authHeader.substring(7);

            Claims claims = extractClaims(token);

            // 3. Forward useful claims as headers to downstream services
            exchange = exchange.mutate()
                    .request(r -> r
                            .header("X-Auth-User-Email", claims.getSubject())
                            .header("X-Auth-User-Id",
                                    claims.get("userId") != null
                                            ? claims.get("userId").toString()
                                            : "")
                    )
                    .build();

            log.info("JWT valid for subject: {}", claims.getSubject());
            return chain.filter(exchange);
        };
    }

    private Claims extractClaims(String token) {
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public static class Config {
    }
}