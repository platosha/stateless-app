package com.example.application.auth;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;
import org.springframework.web.filter.GenericFilterBean;

@Component
public class JwtSplitCookieFilter extends GenericFilterBean implements Filter {
    public static final String JWT_HEADER_AND_PAYLOAD_COOKIE_NAME = "jwt.headerAndPayload";
    public static final String JWT_SIGNATURE_COOKIE_NAME = "jwt.signature";

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);

        final String tokenFromSplitCookies = getTokenFromSplitCookies(
                (HttpServletRequest) request);
        if (tokenFromSplitCookies != null) {
            HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(
                    (HttpServletRequest) request) {
                @Override
                public String getHeader(String headerName) {
                    if ("Authorization".equals(headerName)) {
                        return "Bearer " + tokenFromSplitCookies;
                    }
                    return super.getHeader(headerName);
                }
            };
            chain.doFilter(requestWrapper, response);
        } else {
            chain.doFilter(request, response);
        }

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();
        if (authentication == null) {
            // Token authentication failed — remove the cookies
            removeJwtSplitCookies((HttpServletRequest) request,
                    (HttpServletResponse) response);
        } else {
            setJwtSplitCookiesIfNecessary((HttpServletRequest) request,
                    (HttpServletResponse) response, authentication);
        }
    }

    private String getTokenFromSplitCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        Cookie jwtHeaderAndPayload = Stream.of(cookies)
                .filter(cookie -> JWT_HEADER_AND_PAYLOAD_COOKIE_NAME
                        .equals(cookie.getName())).findFirst().orElse(null);
        if (jwtHeaderAndPayload == null) {
            return null;
        }

        Cookie jwtSignature = Stream.of(cookies)
                .filter(cookie -> JWT_SIGNATURE_COOKIE_NAME
                        .equals(cookie.getName())).findFirst().orElse(null);
        if (jwtSignature == null) {
            return null;
        }

        return jwtHeaderAndPayload.getValue() + "." + jwtSignature.getValue();
    }

    private void setJwtSplitCookiesIfNecessary(HttpServletRequest request,
            HttpServletResponse response, Authentication authentication) {
        final long EXPIRES_IN = 3600L;

        final Date now = new Date();

        final String rolePrefix = "ROLE_";
        final String scope = authentication.getAuthorities().stream()
                .map(Objects::toString).filter(a -> a.startsWith(rolePrefix))
                .map(a -> a.substring(rolePrefix.length()))
                .collect(Collectors.joining(" "));

        SignedJWT signedJWT;
        try {
            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;
            JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
            JWKSelector jwkSelector = new JWKSelector(
                    JWKMatcher.forJWSHeader(jwsHeader));

            List<JWK> jwks = this.jwkSource.get(jwkSelector, null);
            JWK jwk = jwks.get(0);

            JWSSigner signer = new DefaultJWSSignerFactory()
                    .createJWSSigner(jwk, jwsAlgorithm);
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(authentication.getName()).issuer("statelessapp")
                    .issueTime(now)
                    .expirationTime(new Date(now.getTime() + EXPIRES_IN))
                    .claim("scope", scope).build();
            signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                    claimsSet);
            signedJWT.sign(signer);

            Cookie headerAndPayload = new Cookie(
                    JwtSplitCookieFilter.JWT_HEADER_AND_PAYLOAD_COOKIE_NAME,
                    new String(signedJWT.getSigningInput(),
                            StandardCharsets.UTF_8));
            headerAndPayload.setSecure(true);
            headerAndPayload.setHttpOnly(false);
            headerAndPayload.setPath(request.getContextPath() + "/");
            headerAndPayload.setMaxAge((int) EXPIRES_IN - 1);
            response.addCookie(headerAndPayload);

            Cookie signature = new Cookie(
                    JwtSplitCookieFilter.JWT_SIGNATURE_COOKIE_NAME,
                    signedJWT.getSignature().toString());
            signature.setHttpOnly(true);
            signature.setSecure(true);
            signature.setPath(request.getContextPath() + "/");
            signature.setMaxAge((int) EXPIRES_IN - 1);
            response.addCookie(signature);
        } catch (JOSEException e) {
            e.printStackTrace();
        }

    }

    private void removeJwtSplitCookies(HttpServletRequest request,
            HttpServletResponse response) {
        Cookie jwtHeaderAndPayloadRemove = new Cookie(
                JWT_HEADER_AND_PAYLOAD_COOKIE_NAME, null);
        jwtHeaderAndPayloadRemove.setPath(request.getContextPath() + "/");
        jwtHeaderAndPayloadRemove.setMaxAge(0);
        jwtHeaderAndPayloadRemove.setSecure(request.isSecure());
        jwtHeaderAndPayloadRemove.setHttpOnly(false);
        response.addCookie(jwtHeaderAndPayloadRemove);

        Cookie jwtSignatureRemove = new Cookie(JWT_SIGNATURE_COOKIE_NAME, null);
        jwtSignatureRemove.setPath(request.getContextPath() + "/");
        jwtSignatureRemove.setMaxAge(0);
        jwtSignatureRemove.setSecure(request.isSecure());
        jwtSignatureRemove.setHttpOnly(true);
        response.addCookie(jwtSignatureRemove);
    }
}
