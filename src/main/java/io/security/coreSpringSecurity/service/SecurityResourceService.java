package io.security.coreSpringSecurity.service;

import io.security.coreSpringSecurity.domain.entity.Resources;
import io.security.coreSpringSecurity.repository.AccessIpRepository;
import io.security.coreSpringSecurity.repository.ResourcesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

public class SecurityResourceService {
    private ResourcesRepository resourcesRepository;
    private AccessIpRepository accessIpRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
        this.resourcesRepository = resourcesRepository;
        this.accessIpRepository = accessIpRepository;
    }


    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList(){
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(re -> {
            List<ConfigAttribute> configAttributes = new ArrayList<>();
            //하나의 자원에 해당되는 모든Role
            re.getRoleSet().forEach(role -> {
                configAttributes.add(new SecurityConfig(role.getRoleName()));
            });
            result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributes);
        });
        return result;
    }

    public List<String> getAccessIpList() {
        return accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());
    }
}
