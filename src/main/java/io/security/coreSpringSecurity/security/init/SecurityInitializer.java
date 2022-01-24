package io.security.coreSpringSecurity.security.init;

import io.security.coreSpringSecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
public class SecurityInitializer implements ApplicationRunner {

    @Autowired
    private RoleHierarchyService roleHierarchyService;

    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        //어플리케이션 등록 시점에 넣어준다.
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        //어플리케이션 run 시점에 roleHierarchy를 조회하여 넣어준다.
        roleHierarchy.setHierarchy(allHierarchy);

    }
}
