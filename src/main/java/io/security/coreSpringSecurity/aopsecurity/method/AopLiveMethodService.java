package io.security.coreSpringSecurity.aopsecurity.method;

import org.springframework.stereotype.Service;

@Service
public class AopLiveMethodService {
    public void liveMethodSecured(){

        System.out.println("liveMethodSecured");
    }
}
