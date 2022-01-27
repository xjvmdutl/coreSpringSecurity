package io.security.coreSpringSecurity.aopsecurity.method;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
@Service
@Slf4j
public class AopMethodService {

    public void methodSecured() {

        System.out.println("methodSecured");
    }

    public void innerCallMethodTest() {
        log.debug("innerCallMethodTest");
    }
}