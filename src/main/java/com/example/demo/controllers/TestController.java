package com.example.demo.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/user")
    public String getUserPage(){
        return "user page";
    }

    @GetMapping("/admin")
    public String getAdminPage(){
        return "admin page";
    }
}
