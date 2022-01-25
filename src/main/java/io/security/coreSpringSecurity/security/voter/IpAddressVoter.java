package io.security.coreSpringSecurity.security.voter;

import io.security.coreSpringSecurity.service.SecurityResourceService;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        //인증정보, Location, 권한정보

        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();//사용자의 IP주소를 얻을수 있다.
        String remoteAddress = details.getRemoteAddress();// IP 주소

        List<String> accessIpList = securityResourceService.getAccessIpList();
        int result = ACCESS_DENIED; //기본값
        for (String ipAddress : accessIpList){
            if(remoteAddress.equals(ipAddress))
                return ACCESS_ABSTAIN; //다른 심의를 하기 위해 GRANT가 아닌 ABSTAIN 리턴
        }
        if(result == ACCESS_DENIED){
            throw new AccessDeniedException("Invalid IpAddress");
            //예외를 발생시켜 더이상 인증 안되게 한다.
        }
        return result;
    }
}
