package com.example.springsecurity.controller;

import com.example.springsecurity.model.UserLoginRequest;
import com.example.springsecurity.model.UserRegisterRequest;
import com.example.springsecurity.security.JwtUtils;
import com.example.springsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtils jwtUtils;
    private final UserService userService;

    @PostMapping("/login")
    public String login(@RequestBody UserLoginRequest userLoginRequest){
        return this.userService.login(userLoginRequest);
    }

    @PostMapping("/register")
    public String register(@RequestBody UserRegisterRequest userRegisterRequest){
        return userService.register(userRegisterRequest);
    }
}
