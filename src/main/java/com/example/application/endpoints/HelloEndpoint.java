package com.example.application.endpoints;

import javax.annotation.security.RolesAllowed;

import com.vaadin.flow.server.connect.Endpoint;

@Endpoint
public class HelloEndpoint {
    @RolesAllowed("user")
    public String getGreeting(String name) {
        return "Hello, " + name;
    }
}
