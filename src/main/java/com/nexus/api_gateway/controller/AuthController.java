package com.nexus.api_gateway.controller;

import com.nexus.api_gateway.dto.LoginRequest;
import com.nexus.api_gateway.dto.LoginResponse;
import com.nexus.api_gateway.security.JwtUtil;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * AuthController handles authentication-related endpoints.
 * Replaced Lombok with a constructor for dependency injection.
 */
@RestController
@RequestMapping("/nexus/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final WebClient webClient;


    /**
     * Replaces Lombok's @RequiredArgsConstructor
     */
    public AuthController(JwtUtil jwtUtil, WebClient webClient) {
        this.jwtUtil = jwtUtil;
        this.webClient = webClient;
    }


    @PostMapping("/login")
    public Mono<ResponseEntity<?>> login(@RequestBody LoginRequest request) {
        return webClient.post()
                .uri("http://localhost:3000/api/v1/auth/validate-user")
                .bodyValue(request)
                .retrieve()
                .onStatus(
                        status -> status.isError(),
                        clientResponse -> Mono.error(new RuntimeException("Invalid credentials"))
                )
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(map -> {
                    Object dataObj = map.get("data");
                    if (!(dataObj instanceof Map)) {
                        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials"));
                    }
                    Map<String, Object> userMap = (Map<String, Object>) dataObj;
                    String email = (String) userMap.get("email");
                    List<String> roles = (List<String>) userMap.get("roles");
                    if (email == null || roles == null) {
                        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials"));
                    }
                    String token = jwtUtil.generateToken(email, roles);
                    LoginResponse loginResponse = new LoginResponse(token, "Login successful");
                    return Mono.just(ResponseEntity.ok(loginResponse));
                })
                .onErrorResume(error -> Mono.just(
                        ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body("Authentication failed: " + error.getMessage())
                ));
    }
}
