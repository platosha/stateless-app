package com.example.application.auth;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import com.example.application.jose.SecretKeySource;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class StatelessLoginHandler {
    private AuthenticationManager authenticationManager;

    private HttpServletRequest httpServletRequest;

    public StatelessLoginHandler(AuthenticationManager authenticationManager,
            HttpServletRequest httpServletRequest) {
        this.authenticationManager = authenticationManager;
        this.httpServletRequest = httpServletRequest;
    }

    @PostMapping(value = "/auth/token", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public Map<String, String> getToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            HttpServletResponse response) {
        if (!"password".equals(grantType)) {
            throw new RuntimeException("unsupported_grant_type");
        }

        final long EXPIRES_IN = 3600L;

        Authentication authentication;

        try {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    username, password);
            usernamePasswordAuthenticationToken.setDetails(
                    new WebAuthenticationDetails(httpServletRequest));

            authentication = authenticationManager
                    .authenticate(usernamePasswordAuthenticationToken);
        } catch (Exception exception) {
            throw new RuntimeException("invalid_grant");
        }

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
                SplitCookieToBearerTokenConverterFilter.JWT_HEADER_AND_PAYLOAD,
                new String(signedJWT.getSigningInput(),
                        StandardCharsets.UTF_8));
        headerAndPayload.setSecure(true);
        headerAndPayload.setHttpOnly(false);
        headerAndPayload.setPath("/");
        headerAndPayload.setMaxAge((int) EXPIRES_IN - 1);
        response.addCookie(headerAndPayload);

        Cookie signature = new Cookie(
                SplitCookieToBearerTokenConverterFilter.JWT_SIGNATURE,
                signedJWT.getSignature().toString());
        signature.setHttpOnly(true);
        signature.setSecure(true);
        signature.setPath("/");
        signature.setMaxAge((int) EXPIRES_IN - 1);
        response.addCookie(signature);

        final Map<String, String> responseBody = new HashMap<>();
        responseBody.put("access_token", signedJWT.serialize());
        responseBody.put("token_type", "Bearer");
        responseBody.put("expires_in", String.valueOf(EXPIRES_IN));
        return responseBody;
    }
}
