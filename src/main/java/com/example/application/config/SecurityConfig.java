package com.example.application.config;

import com.example.application.jose.SecretKeySource;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //
    // Configuration to enable JWT for endpoints
    //

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        // @formatter:on
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        // Converter from "scope" claims in JWT into ROLE_ prefixed authorities.
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter
                .setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    //
    // Use built-in secret key for JWT verification
    //

    @Bean
    JwtDecoder jwtDecoder() {
        // JWT decoder trusting a symmetric secret key to verify JWTs.
        return NimbusJwtDecoder.withSecretKey(SecretKeySource.get()).build();
    }

    //
    // Configuration for StatelessLoginHandler
    //

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

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
