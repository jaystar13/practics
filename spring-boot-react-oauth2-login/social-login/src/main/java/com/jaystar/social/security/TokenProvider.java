package com.jaystar.social.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.stream.Collectors;

@Setter
@Getter
@ConfigurationProperties("jwt")
@Component
public class TokenProvider {

    private String key;
    private SecretKey secretKey;
    private Long tokenValidityTime;

    private static final String KEY_ROLE = "role";

    @PostConstruct
    private void init() {
        secretKey = Keys.hmacShaKeyFor(key.getBytes());
    }

    public String generateToken(Authentication authentication) {
        Date now = new Date();
        Date expireDate = new Date(now.getTime() + tokenValidityTime);

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining());

        return Jwts.builder()
                .subject(authentication.getName())
                .claim(KEY_ROLE, authorities)
                .issuedAt(now)
                .expiration(expireDate)
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }
}
