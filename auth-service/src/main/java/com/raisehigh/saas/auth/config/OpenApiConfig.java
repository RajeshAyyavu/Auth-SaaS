package com.raisehigh.saas.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI authServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Auth-SaaS API Documentation")
                        .description("Production-ready authentication service for SaaS applications. Includes Signup, Login, JWT, and Refresh Token flows.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("RaiseHigh Tech")
                                .email("info@raisehigh.tech")
                                .url("https://github.com/RajeshAyyavu/Auth-SaaS")
                        )
                );
    }
}
