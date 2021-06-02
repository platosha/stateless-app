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
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.security.core.context.SecurityContextHolder;

public class SplitCookieToBearerTokenConverterFilter implements Filter {
    public static final String JWT_HEADER_AND_PAYLOAD_COOKIE_NAME = "jwt.headerAndPayload";
    public static final String JWT_SIGNATURE_COOKIE_NAME = "jwt.signature";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        Cookie[] cookies = ((HttpServletRequest) request).getCookies();
        if (cookies == null) {
            chain.doFilter(request, response);
            return;
        }

        Optional<Cookie> jwtHeaderAndPayload = Stream.of(cookies)
                .filter(cookie -> JWT_HEADER_AND_PAYLOAD_COOKIE_NAME
                        .equals(cookie.getName())).findFirst();
        Optional<Cookie> jwtSignature = Stream.of(cookies)
                .filter(cookie -> JWT_SIGNATURE_COOKIE_NAME.equals(cookie.getName()))
                .findFirst();

        if (jwtHeaderAndPayload.isPresent() && jwtSignature.isPresent()) {
            final String jwt = jwtHeaderAndPayload.get().getValue() + "." +
                    jwtSignature.get().getValue();
            HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(
                    (HttpServletRequest) request) {
                @Override
                public String getHeader(String headerName) {
                    if ("Authorization".equals(headerName)) {
                        return "Bearer " + jwt;
                    }
                    return super.getHeader(headerName);
                }
            };
            chain.doFilter(requestWrapper, response);

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                // Token authentication failed — remove the cookies
                Cookie jwtHeaderAndPayloadRemove =
                        new Cookie(JWT_HEADER_AND_PAYLOAD_COOKIE_NAME, null);
                jwtHeaderAndPayloadRemove.setPath(((HttpServletRequest) request).getContextPath() + "/");
                jwtHeaderAndPayloadRemove.setMaxAge(0);
                jwtHeaderAndPayloadRemove.setSecure(request.isSecure());
                jwtHeaderAndPayloadRemove.setHttpOnly(false);
                ((HttpServletResponse) response).addCookie(jwtHeaderAndPayloadRemove);

                Cookie jwtSignatureRemove =
                        new Cookie(JWT_SIGNATURE_COOKIE_NAME, null);
                jwtSignatureRemove.setPath(((HttpServletRequest) request).getContextPath() +
                        "/");
                jwtSignatureRemove.setMaxAge(0);
                jwtSignatureRemove.setSecure(request.isSecure());
                jwtSignatureRemove.setHttpOnly(true);
                ((HttpServletResponse) response).addCookie(jwtSignatureRemove);
            }
        } else {
            chain.doFilter(request, response);
        }
    }
}
