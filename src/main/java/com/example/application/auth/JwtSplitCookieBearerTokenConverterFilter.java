package com.example.application.auth;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;

public class JwtSplitCookieBearerTokenConverterFilter implements Filter {
    JwtSplitCookieService jwtSplitCookieService;

    public JwtSplitCookieBearerTokenConverterFilter(JwtSplitCookieService jwtSplitCookieService) {
        this.jwtSplitCookieService = jwtSplitCookieService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        final String tokenFromSplitCookies = jwtSplitCookieService
                .getTokenFromSplitCookies((HttpServletRequest) request);
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
    }

}
