package io.security.coreSpringSecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.coreSpringSecurity.domain.AccountDto;
import io.security.coreSpringSecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    
    private ObjectMapper objectMapper = new ObjectMapper();//JSON 객체를 추출하고 반환하기위해
    
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login")); //사용자가 해당 URL로 요청을 할떄만 필터가 동작
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if(!isAjax(request)){   //AJAX인가?
            throw new IllegalStateException("Authentication is not supported");
        }

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalArgumentException("Username or Password is empty");
        }
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
        //현재는 Form인증 방식을 AuthenticationProvider 가 동작하게 되는데 Token 이 AjaxAuthenticationToken 과 다르기 떄문에 현재는 동작하지 않는다.

        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    private boolean isAjax(HttpServletRequest request) {
        //header에 값을 담아서 Ajax인지 판단.
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-with"))){
            return true;
        }
        return false;
    }
}
