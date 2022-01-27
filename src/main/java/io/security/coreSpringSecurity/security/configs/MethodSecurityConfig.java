package io.security.coreSpringSecurity.security.configs;//package io.security.coreSpringSecurity.security.configs;

import io.security.coreSpringSecurity.security.factory.MethodResourcesFactoryBean;
import io.security.coreSpringSecurity.security.interceptor.CustomMethodSecurityInterceptor;
import io.security.coreSpringSecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.coreSpringSecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Map;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration { //메소드 관련 빈을 초기화

    @Autowired
    private SecurityResourceService securityResourceService;

    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        //해당 메소드를 Override 한다.
        return mapBasedMethodSecurityMetadataSource(); //생성자로 DB를 통해 얻은 데이터를 전달해야한다.
    }
    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
        return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
    }
    @Bean
    public MethodResourcesFactoryBean methodResourcesMapFactoryBean() {
        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("method");
        return methodResourcesFactoryBean;
    }
    @Bean
    public MethodResourcesFactoryBean pointcutResourcesMapFactoryBean() {
        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("pointcut");
        return methodResourcesFactoryBean;
    }

    @Bean
    public ProtectPointcutPostProcessor protectPointcutPostProcessor(){
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());
        return protectPointcutPostProcessor;
    }


    @Bean
    public CustomMethodSecurityInterceptor customMethodSecurityInterceptor(MapBasedMethodSecurityMetadataSource methodSecurityMetadataSource) {
        CustomMethodSecurityInterceptor customMethodSecurityInterceptor =  new CustomMethodSecurityInterceptor();
        customMethodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
        customMethodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
        customMethodSecurityInterceptor.setSecurityMetadataSource(methodSecurityMetadataSource);
        RunAsManager runAsManager = runAsManager();
        if (runAsManager != null) {
            customMethodSecurityInterceptor.setRunAsManager(runAsManager);
        }

        return customMethodSecurityInterceptor;
    }

    /*
    @Bean
    BeanPostProcessor protectPointcutPostProcessor() throws Exception{
        //빈을 생성하기 위해 리플랙션 사용

        Class<?> clazz = Class.forName("org.springframework.security.config.method.MethodSecurityBeanDefinitionParser$PreAuthorizeAuthorizationMethodInterceptor");
        Constructor<?> declareConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
        declareConstructor.setAccessible(true);
        Object instance = declareConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
        setPointcutMap.setAccessible(true);
        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());
        return (BeanPostProcessor) instance;
    }
     */

}