package io.security.coreSpringSecurity.security.provider;

import io.security.coreSpringSecurity.security.common.FormWebAuthenticationDetails;
import io.security.coreSpringSecurity.security.service.AccountContext;
import io.security.coreSpringSecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials(); //authentication에서 입력한 값을 가지고 올수 있다.
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialsException"); //패스워드 일치 X
        }

        AjaxAuthenticationToken ajaxAuthenticationToken
                = new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return ajaxAuthenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        //AjaxAuthenticationToken인지 확인
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
