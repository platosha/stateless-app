package com.example.application.auth;

import org.springframework.security.core.Authentication;

public interface JwtClaimsSource {
    JwtClaims getClaimsFor(Authentication p);
}
