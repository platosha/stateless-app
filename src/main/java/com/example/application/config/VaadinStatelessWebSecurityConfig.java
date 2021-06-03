package com.example.application.config;

import java.util.HashSet;
import java.util.Set;

import com.example.application.auth.JwtSplitCookieFilter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;

import com.vaadin.flow.spring.security.VaadinWebSecurityConfigurerAdapter;

public class VaadinStatelessWebSecurityConfig
        extends VaadinWebSecurityConfigurerAdapter {
    private void applyJwtWithSplitCookieSecurity(HttpSecurity http)
            throws Exception {
        // @formatter:off
        http
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .addFilterBefore(new JwtSplitCookieFilter(),
                        BearerTokenAuthenticationFilter.class);
        // @formatter:on
    }

    protected void setLoginView(HttpSecurity http, String fusionLoginViewPath,
            String logoutUrl) throws Exception {
        // @formatter:off
        http
                .formLogin()
                    .loginPage(fusionLoginViewPath).permitAll()
                    .and()
                .logout()
                    .logoutUrl(logoutUrl);
        applyJwtWithSplitCookieSecurity(http);
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
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        Set<JWSAlgorithm> jwsAlgorithmSet = new HashSet<>();
        jwsAlgorithmSet.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgorithmSet.addAll(JWSAlgorithm.Family.EC);
        jwsAlgorithmSet.addAll(JWSAlgorithm.Family.HMAC_SHA);
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
                jwsAlgorithmSet, jwkSource);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claimsSet, context) -> {
        });
        return new NimbusJwtDecoder(jwtProcessor);
    }
}