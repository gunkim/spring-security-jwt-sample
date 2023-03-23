package io.github.gunkim.application.spring.endpoint;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/say")
public class HomeController {
    @GetMapping("/adminHello")
    public String adminHello(){
        return "Hello!";
    }
    @GetMapping("/userHello")
    public String userHello(){
        return "Hello!";
    }
}
