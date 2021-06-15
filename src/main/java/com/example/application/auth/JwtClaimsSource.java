package com.example.application.auth;

import java.util.function.Function;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClaimAccessor;

public interface JwtClaimsSource
        extends Function<Authentication, ClaimAccessor> {
}
