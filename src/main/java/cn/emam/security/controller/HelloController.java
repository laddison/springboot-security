package cn.emam.security.controller;

import cn.emam.security.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * hello控制器
 * @author LiQiuShui
 */
@RestController
public class HelloController {

    private MyUserDetailsService myUserDetailsService;

    @Autowired
    public void setMyUserDetailsService(MyUserDetailsService myUserDetailsService) {
        this.myUserDetailsService = myUserDetailsService;
    }

    @GetMapping("/hi")
    public String say() {
        myUserDetailsService.getRoles();
        return "hello";
    }
}
