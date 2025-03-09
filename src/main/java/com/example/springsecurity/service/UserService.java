package com.example.springsecurity.service;

import com.example.springsecurity.entity.Role;
import com.example.springsecurity.entity.User;
import com.example.springsecurity.model.UserLoginRequest;
import com.example.springsecurity.model.UserRegisterRequest;
import com.example.springsecurity.repository.RoleRepository;
import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final JwtUtils jwtUtils;

    public String register(UserRegisterRequest userRegisterRequest) {
        User user = new User();
        user.setUsername(userRegisterRequest.getUsername());
        user.setPassword(passwordEncoder.encode(userRegisterRequest.getPassword()));
        Role role = roleRepository.findByName("ROLE_USER");
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setRoles(roles);
        userRepository.save(user);

        return "User successfully registered";
    }


    public String login(UserLoginRequest userLoginRequest) {

        User user = this.userRepository.findByUsername(userLoginRequest.getUsername());

        if(passwordEncoder.matches(userLoginRequest.getPassword(), user.getPassword())) {
            return jwtUtils.generateJwtToken(user.getUsername(),
                    user.getRoles().stream().map(Role::getName).toList());
        }

        throw new BadCredentialsException("Invalid username or password");
    }
}
