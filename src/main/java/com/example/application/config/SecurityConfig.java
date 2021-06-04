package com.example.application.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@EnableWebSecurity
public class SecurityConfig extends VaadinStatelessWebSecurityConfig {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        super.configure(http);

        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        setJwtSplitCookieAuthentication(http, "statelessapp", 3600,
                JWSAlgorithm.HS256);
        setLoginView(http, "/login", "/logout");
        // @formatter:on
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        OctetSequenceKey key = new OctetSequenceKey.Builder(
                Base64URL.from("I72kIcB1UrUQVHVUAzgweE+BLc0bF8mLv9SmrgKsQAk="))
                .algorithm(JWSAlgorithm.HS256).build();
        JWKSet jwkSet = new JWKSet(key);
        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
        // @formatter:off
        auth
                .inMemoryAuthentication()
                .withUser("user").password("{noop}user").roles("user")
                .and()
                .withUser("admin").password("{noop}admin").roles("user",
                "admin");
        // @formatter:on
    }
}
