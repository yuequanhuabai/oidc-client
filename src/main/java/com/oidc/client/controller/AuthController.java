package com.oidc.client.controller;

import com.oidc.client.dto.TokenExchangeRequest;
import com.oidc.client.dto.TokenResponse;
import com.oidc.client.dto.UserInfo;
import com.oidc.client.service.OidcClientService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
@Slf4j
public class AuthController {

    private final OidcClientService oidcClientService;

    @PostMapping("/token")
    public ResponseEntity<?> exchangeToken(@RequestBody TokenExchangeRequest request) {
        if (request.getCode() == null || request.getCode().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body("{\"error\": \"invalid_request\", \"message\": \"Missing authorization code\"}");
        }

        TokenResponse tokenResponse = oidcClientService.exchangeCodeForToken(request.getCode());

        if (tokenResponse != null) {
            log.info("✓ Token exchange successful for user: {}", tokenResponse.getUsername());
            return ResponseEntity.ok(tokenResponse);
        } else {
            log.warn("✗ Token exchange failed for code: {}", request.getCode());
            return ResponseEntity.badRequest()
                    .body("{\"error\": \"invalid_grant\", \"message\": \"Failed to exchange authorization code\"}");
        }
    }

    @GetMapping("/user")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        Long userId = (Long) request.getAttribute("userId");
        String username = (String) request.getAttribute("username");

        if (userId == null || username == null) {
            return ResponseEntity.status(401)
                    .body("{\"error\": \"unauthorized\", \"message\": \"User not authenticated\"}");
        }

        UserInfo userInfo = UserInfo.builder()
                .userId(userId)
                .username(username)
                .build();

        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok("{\"status\": \"ok\"}");
    }

    /**
     * 登出端点 - 清除 HttpOnly Cookies
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        // 清除 access_token Cookie
        Cookie accessTokenCookie = new Cookie("access_token", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);  // 立即过期
        response.addCookie(accessTokenCookie);

        // 清除 id_token Cookie
        Cookie idTokenCookie = new Cookie("id_token", null);
        idTokenCookie.setHttpOnly(true);
        idTokenCookie.setSecure(false);
        idTokenCookie.setPath("/");
        idTokenCookie.setMaxAge(0);
        response.addCookie(idTokenCookie);

        // 清除 username Cookie
        Cookie usernameCookie = new Cookie("username", null);
        usernameCookie.setHttpOnly(false);
        usernameCookie.setSecure(false);
        usernameCookie.setPath("/");
        usernameCookie.setMaxAge(0);
        response.addCookie(usernameCookie);

        log.info("✓ User logged out, cookies cleared");
        return ResponseEntity.ok("{\"message\": \"Logged out successfully\"}");
    }
}
