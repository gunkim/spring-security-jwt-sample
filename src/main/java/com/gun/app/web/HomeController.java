package com.gun.app.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 테스트용 컨트롤러
 */
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