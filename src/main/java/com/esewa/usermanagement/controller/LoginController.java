package com.esewa.usermanagement.controller;

import com.esewa.usermanagement.dto.JwtResponse;
import com.esewa.usermanagement.dto.LoginDto;
import com.esewa.usermanagement.service.impl.LoginServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/homepage")
@RequiredArgsConstructor
public class LoginController {

    private final LoginServiceImpl loginService;

    @Value("${spring.datasource.password}")
    private String databasePassword;

    @Value("${jwt.secret.key}")
    private String jwtKey;

    @GetMapping
    public void homePage(HttpServletRequest request){
        String servletPath = request.getServletPath();
        log.info("In Homepage. Servlet path: {}. Jwt Key: {}", servletPath, jwtKey);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody LoginDto credentials){
        return loginService.loginUser(credentials);
    }

}
