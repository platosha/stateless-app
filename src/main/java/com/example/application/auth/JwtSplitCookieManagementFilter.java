package com.example.application.auth;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class JwtSplitCookieManagementFilter implements Filter {
    private JwtSplitCookieService jwtSplitCookieService;

    public JwtSplitCookieManagementFilter(JwtSplitCookieService jwtSplitCookieService) {
        this.jwtSplitCookieService = jwtSplitCookieService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        if (authentication == null ||
                authentication instanceof AnonymousAuthenticationToken) {
            // Token authentication failed — remove the cookies
            jwtSplitCookieService
                    .removeJwtSplitCookies((HttpServletRequest) request,
                            (HttpServletResponse) response);
        } else {
            // TODO: update token to prevent premature expiration
//            jwtSplitCookieService
//                    .setJwtSplitCookiesIfNecessary((HttpServletRequest) request,
//                            (HttpServletResponse) response, authentication);
        }

        chain.doFilter(request, response);
    }

}
