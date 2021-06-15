package com.example.application.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.example.application.auth.JwtClaimsSource;
import com.example.application.auth.JwtSplitCookieBearerTokenConverterFilter;
import com.example.application.auth.JwtSplitCookieManagementFilter;
import com.example.application.auth.JwtSplitCookieService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import com.vaadin.flow.spring.security.VaadinWebSecurityConfigurerAdapter;

public class VaadinStatelessWebSecurityConfig
        extends VaadinWebSecurityConfigurerAdapter {
    protected void setJwtSplitCookieAuthentication(HttpSecurity http,
            String issuer, long expires_in, JWSAlgorithm algorithm)
            throws Exception {
        setJwtSplitCookieAuthentication(http, issuer, expires_in, algorithm,
                (context) -> new OidcUserInfo(Collections.emptyMap()));
    }

    @SuppressWarnings("unchecked")
    protected void setJwtSplitCookieAuthentication(HttpSecurity http,
            String issuer, long expires_in, JWSAlgorithm algorithm,
            JwtClaimsSource jwtClaimsSource) throws Exception {
        final JwtSplitCookieService jwtSplitCookieService = new JwtSplitCookieService(
                jwtClaimsSource);

        // @formatter:off
        http
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .addFilterAfter(new JwtSplitCookieBearerTokenConverterFilter(jwtSplitCookieService),
                        SecurityContextPersistenceFilter.class)
                .addFilterAfter(new JwtSplitCookieManagementFilter(jwtSplitCookieService),
                        SwitchUserFilter.class);
        // @formatter:on

        Arrays.asList(FormLoginConfigurer.class, OAuth2LoginConfigurer.class)
                .forEach(loginConfigurerCls -> http
                        .getConfigurers(loginConfigurerCls).forEach(
                                login -> ((AbstractAuthenticationFilterConfigurer) login)
                                        .successHandler(
                                                (request, response, authentication) -> {
                                                    jwtSplitCookieService
                                                            .setJwtSplitCookiesIfNecessary(
                                                                    request,
                                                                    response,
                                                                    authentication);
                                                    response.sendRedirect("/");
                                                })));

        http.getConfigurers(LogoutConfigurer.class).forEach(
                logout -> ((LogoutConfigurer) logout).addLogoutHandler(
                        ((request, response, authentication) -> {
                            jwtSplitCookieService
                                    .removeJwtSplitCookies(request, response);
                        })));
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
