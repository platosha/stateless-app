package com.example.application.auth;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
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
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponseMapConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class AuthController {
    private AuthenticationManager authenticationManager;

    private HttpServletRequest httpServletRequest;

    public AuthController(AuthenticationManager authenticationManager,
            HttpServletRequest httpServletRequest) {
        this.authenticationManager = authenticationManager;
        this.httpServletRequest = httpServletRequest;
    }

    @PostMapping(value = "/token", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public Map<String, String> getToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam("username") String username,
            @RequestParam("password") String password) {
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

        OAuth2AccessTokenResponse response =
                OAuth2AccessTokenResponse.withToken(signedJWT.serialize())
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(EXPIRES_IN).build();
        return new OAuth2AccessTokenResponseMapConverter().convert(response);
    }

}
