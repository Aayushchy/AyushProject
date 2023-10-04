package com.esewa.usermanagement.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(value = "${external.property.file.path}", ignoreResourceNotFound = true)
public class ExternalPropertyConfig {
}
