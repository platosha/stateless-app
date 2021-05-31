package com.example.application.auth;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.Optional;
import java.util.stream.Stream;

public class SplitCookieToBearerTokenConverterFilter implements Filter {
    public static final String JWT_HEADER_AND_PAYLOAD = "jwt.headerAndPayload";
    public static final String JWT_SIGNATURE = "jwt.signature";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        Cookie[] cookies = ((HttpServletRequest) request).getCookies();
        if (cookies == null) {
            chain.doFilter(request, response);
            return;
        }

        Optional<Cookie> jwtHeaderAndPayload = Stream.of(cookies)
                .filter(cookie -> JWT_HEADER_AND_PAYLOAD
                        .equals(cookie.getName())).findFirst();
        Optional<Cookie> jwtSignature = Stream.of(cookies)
                .filter(cookie -> JWT_SIGNATURE.equals(cookie.getName()))
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
        } else {
            chain.doFilter(request, response);
        }
    }
}
