package io.security.coreSpringSecurity.service.impl;

import io.security.coreSpringSecurity.domain.Account;
import io.security.coreSpringSecurity.repository.UserRepository;
import io.security.coreSpringSecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
