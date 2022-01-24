package io.security.coreSpringSecurity.security.factory;

import io.security.coreSpringSecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;
//DB로 부터 값을 읽어와 자원과 메핑된 정보를 가지고 있어야한다.
public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {
        //securityResourceService가 Map을 만들어 resourcesMap에 넣어줄 것이다
        if(resourcesMap == null){
            //생성해 주어야한다.
            init();
        }
        return resourcesMap;
    }

    private void init() {  //DB로 부터 메핑된 자원을 얻는다
        resourcesMap = securityResourceService.getResourceList();
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
        return FactoryBean.super.isSingleton();
    }
}
