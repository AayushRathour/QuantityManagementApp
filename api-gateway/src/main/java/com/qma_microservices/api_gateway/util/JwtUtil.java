package com.qma_microservices.api_gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

@Component
public class JwtUtil {

    @Value("${security.jwt.secret}")
    private String secret;

    private Key key;

    @PostConstruct
    public void init() {
        // Convert secret string → Key (IMPORTANT)
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // ✅ Validate token
    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ✅ Extract username (or email)
    public String getUsername(String token) {
        return validateToken(token).getSubject();
    }

    // ✅ Extract custom claim (example: userId)
    public Long getUserId(String token) {
        Object userId = validateToken(token).get("userId");
        return userId != null ? Long.parseLong(userId.toString()) : null;
    }

    // ✅ Extract any claim
    public Object getClaim(String token, String key) {
        return validateToken(token).get(key);
    }
}