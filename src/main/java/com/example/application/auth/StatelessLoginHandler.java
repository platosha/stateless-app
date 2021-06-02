package com.example.application.auth;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Objects;
import java.util.stream.Collectors;

import com.example.application.jose.SecretKeySource;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class StatelessLoginHandler implements AuthenticationSuccessHandler {
    public StatelessLoginHandler() {
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response, Authentication authentication)
            throws IOException {
        final long EXPIRES_IN = 3600L;

        final Date now = new Date();

        final String rolePrefix = "ROLE_";
        final String scope = authentication.getAuthorities().stream()
                .map(Objects::toString).filter(a -> a.startsWith(rolePrefix))
                .map(a -> a.substring(rolePrefix.length()))
                .collect(Collectors.joining(" "));

        SignedJWT signedJWT;
        try {
            JWSSigner signer = new MACSigner(SecretKeySource.get());
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(authentication.getName()).issuer("statelessapp")
                    .issueTime(now)
                    .expirationTime(new Date(now.getTime() + EXPIRES_IN))
                    .claim("scope", scope).build();
            signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                    claimsSet);
            signedJWT.sign(signer);
        } catch (Exception exception) {
            throw new RuntimeException("invalid_grant");
        }

        Cookie headerAndPayload = new Cookie(
                SplitCookieToBearerTokenConverterFilter.JWT_HEADER_AND_PAYLOAD_COOKIE_NAME,
                new String(signedJWT.getSigningInput(),
                        StandardCharsets.UTF_8));
        headerAndPayload.setSecure(true);
        headerAndPayload.setHttpOnly(false);
        headerAndPayload.setPath(request.getContextPath() + "/");
        headerAndPayload.setMaxAge((int) EXPIRES_IN - 1);
        response.addCookie(headerAndPayload);

        Cookie signature = new Cookie(
                SplitCookieToBearerTokenConverterFilter.JWT_SIGNATURE_COOKIE_NAME,
                signedJWT.getSignature().toString());
        signature.setHttpOnly(true);
        signature.setSecure(true);
        signature.setPath(request.getContextPath() + "/");
        signature.setMaxAge((int) EXPIRES_IN - 1);
        response.addCookie(signature);

        response.sendRedirect(request.getContextPath() + "/");
    }
}
