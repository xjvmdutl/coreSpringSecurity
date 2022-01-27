package io.security.coreSpringSecurity.security.factory;

import io.security.coreSpringSecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;
@Slf4j
public class MethodResourcesFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private String resourceType;
    private LinkedHashMap<String, List<ConfigAttribute>> resourcesMap;

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }



    public void init() {
        if ("method".equals(resourceType)) {
            resourcesMap = securityResourceService.getMethodResourceList();
        } else if ("pointcut".equals(resourceType)) {
            resourcesMap = securityResourceService.getPointcutResourceList();
        } else {
            log.error("resourceType must be 'method' or 'pointcut'");
        }
    }

    public LinkedHashMap<String, List<ConfigAttribute>> getObject() {
        if (resourcesMap == null) {
            init();
        }
        return resourcesMap;
    }

    @SuppressWarnings("rawtypes")
    public Class<LinkedHashMap> getObjectType() {
        return LinkedHashMap.class;
    }

    public boolean isSingleton() {
        return true;
    }
}
