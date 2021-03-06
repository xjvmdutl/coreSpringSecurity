package io.security.coreSpringSecurity.security.service;

import io.security.coreSpringSecurity.domain.Account;
import io.security.coreSpringSecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService")
public class CustomUserDetailService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);
        if(account == null){
            throw new UsernameNotFoundException("UsernameNotFoundException");
        }
        //UserDetails를 직접 구현해서 작성해야 한다.

        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole())); //DB에 저장된 권한을 준다.
        AccountContext accountContext = new AccountContext(account, roles);//권한을 주어야한다.
        return accountContext;
    }
}
