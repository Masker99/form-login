package com.masker.formlogin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @RequestMapping("/index")
    public String sayHello(){
        return "Hello World!";
    }

    @RequestMapping("/f1")
    public String failureHandler1(){
        return "f1--failureForwardUrl";
    }

    @GetMapping("/f2")
    public String failureHandler2(){
        return "f2--failureUrl";
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/user/hello")
    public String helloUser(){
        return "hello user";
    }

    @GetMapping("/admin/hello")
    public String helloAdmin(){
        return "hello admin";
    }
}
