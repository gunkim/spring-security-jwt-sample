package io.github.gunkim.application.spring.endpoint;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/say")
public class HomeController {
    @GetMapping("/admin")
    public String adminHello() {
        return "Hello!";
    }

    @GetMapping("/user")
    public String userHello() {
        return "Hello!";
    }
}
