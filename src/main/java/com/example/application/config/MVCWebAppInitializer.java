package com.example.application.config;

import java.util.Arrays;
import java.util.Collection;

import com.example.application.auth.StatelessLoginHandler;

import com.vaadin.flow.spring.VaadinMVCWebAppInitializer;

public class MVCWebAppInitializer extends VaadinMVCWebAppInitializer {
    @Override
    protected Collection<Class<?>> getConfigurationClasses() {
        return Arrays.asList(StatelessLoginHandler.class);
    }
}
