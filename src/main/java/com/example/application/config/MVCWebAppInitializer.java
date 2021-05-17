package com.example.application.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import com.example.application.auth.AuthController;

import com.vaadin.flow.spring.VaadinMVCWebAppInitializer;

public class MVCWebAppInitializer extends VaadinMVCWebAppInitializer {
    @Override
    protected Collection<Class<?>> getConfigurationClasses() {
        return Arrays.asList(AuthController.class);
    }
}
