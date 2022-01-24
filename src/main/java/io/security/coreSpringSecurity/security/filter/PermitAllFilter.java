package io.security.coreSpringSecurity.security.filter;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PermitAllFilter extends FilterSecurityInterceptor {

    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    
    //RequestMatcher타입으로 List로 저장
    private List<RequestMatcher> permitAllRequestMatcher = new ArrayList<>();

    //생성자를 통해 PermitAll되는 자원을 입력받는다
    public PermitAllFilter(String... permitAllPattern) {
        createPermitAllPattern(permitAllPattern);
    }
    
    private void createPermitAllPattern(String... permitAllPattern) {
        for (String pattern : permitAllPattern) {
            permitAllRequestMatcher.add(new AntPathRequestMatcher(pattern));
        }

    }


    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {
        boolean permitAll = false;
        HttpServletRequest request = ((FilterInvocation) object).getRequest(); //사용자 요청정보
        for (RequestMatcher requestMatcher : permitAllRequestMatcher) {
            if (requestMatcher.matches(request)) { //사용자 정보 == request정보
                permitAll = true; //인가 처리가 필요 없으므로 flag를 true
                break;
            }
        }

        if (permitAll) { //인가 처리가 필요 없는 상태
            return null; //권한 체크를 하지 않는다.
        }

        return super.beforeInvocation(object);  //권한 처리가 필요한 것은 부모로 인가처리를 넘긴다.
    }

    @Override
    public void invoke(FilterInvocation fi) throws IOException, ServletException {

        if ((fi.getRequest() != null) && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
                && super.isObserveOncePerRequest()) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null) {
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            InterceptorStatusToken token = beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, null);
        }
    }

}
