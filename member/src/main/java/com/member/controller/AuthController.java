package com.member.controller;

import com.member.dto.LoginRequest;
import com.member.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController   // REST API 컨트롤러
@RequestMapping("/api/auth")   // 기본 URL 경로 설정
@RequiredArgsConstructor  // 생성자 주입 자동 생성
public class AuthController {
    private final AuthService authService; // 로그인 서비스


//    @PostMapping("/login")
//    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
//        try {
//            String result = authService.login(request);
//            return ResponseEntity.ok(result); // 200 OK
//        } catch (RuntimeException e) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage()); // 401
//        }
//    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        String token = authService.login(request);
        return ResponseEntity.ok()
                .header("Authorization", "Bearer " + token) // 헤더에 JWT 추가
                .body("로그인 성공");
    }

}
