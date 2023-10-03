package xyz.pplax.oauth.authcode.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import xyz.pplax.oauth.authcode.vo.UserVO;

@RestController
public class ResourceController {

    @GetMapping("/user/{username}")
    public UserVO user(@PathVariable String username){
        return new UserVO(username, username + "@foxmail.com");
    }
}