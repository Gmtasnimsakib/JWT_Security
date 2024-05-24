package org.example.springsecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.example.springsecurity.entity.User;
import org.example.springsecurity.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;

    @GetMapping("/hello")
    public String helloWorld() {
        return "Welcome To The Website.";
    }

    @PostMapping("/login")
    public String login(@RequestBody User user) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            if (authentication.isAuthenticated()) {
                
                return jwtService.genarateToken(user.getUsername());
            }
        } catch (Exception e) {
            return "Invalid Username or Password";
        }
        return "User Not Logged in";
    }
}