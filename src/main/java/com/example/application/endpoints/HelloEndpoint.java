package com.example.application.endpoints;

import javax.annotation.security.RolesAllowed;

import org.springframework.beans.factory.annotation.Autowired;

import com.vaadin.flow.server.connect.Endpoint;

@Endpoint
public class HelloEndpoint {
    @RolesAllowed("USER")
    public String getGreeting(String name) {
        return "Hello, " + name;
    }
}
