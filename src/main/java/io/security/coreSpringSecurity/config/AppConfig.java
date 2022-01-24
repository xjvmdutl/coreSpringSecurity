package io.security.coreSpringSecurity.config;

import io.security.coreSpringSecurity.repository.ResourcesRepository;
import io.security.coreSpringSecurity.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository){
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
        return securityResourceService;
    }

}
