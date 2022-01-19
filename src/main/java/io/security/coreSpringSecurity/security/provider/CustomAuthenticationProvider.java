package io.security.coreSpringSecurity.security.provider;

import io.security.coreSpringSecurity.security.common.FormWebAuthenticationDetails;
import io.security.coreSpringSecurity.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //인증을 위한 정보가 들어간다.

        String username = authentication.getName();
        String password = (String) authentication.getCredentials(); //authentication에서 입력한 값을 가지고 올수 있다.
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialsException"); //패스워드 일치 X
        }

        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails)authentication.getDetails();
        //내가 저장한 Details값
        String secretKey = details.getSecretKey();
        if(secretKey == null && !"secret".equals(secretKey)){
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException"); //인증 에러
        }


        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return usernamePasswordAuthenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        //UsernamePasswordAuthenticationToken 과 authentication 타입이 같다면 인증처리를 해라
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
