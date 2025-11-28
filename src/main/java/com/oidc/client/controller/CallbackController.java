package com.oidc.client.controller;

import com.oidc.client.dto.TokenResponse;
import com.oidc.client.service.OidcClientService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@AllArgsConstructor
@Slf4j
public class CallbackController {

    private final OidcClientService oidcClientService;

    @GetMapping("/callback")
    public String handleCallback(@RequestParam String code,
                                  @RequestParam(required = false) String state,
                                  HttpServletResponse response) {
        log.info("Received authorization code: {} with state: {}", code, state);

        // 验证 state 参数是否存在（CSRF 防护）
        if (state == null || state.isEmpty()) {
            log.warn("✗ Missing state parameter - potential CSRF attack");
            return "redirect:http://localhost:5173/?error=invalid_state";
        }

        try {
            // 用授权码换取 token
            TokenResponse tokenResponse = oidcClientService.exchangeCodeForToken(code);

            if (tokenResponse != null) {
                log.info("✓ Token exchange successful for user: {}", tokenResponse.getUsername());

                // 设置 Access Token 为 HttpOnly Cookie（防 XSS 攻击）
                Cookie accessTokenCookie = new Cookie("access_token", tokenResponse.getAccessToken());
                accessTokenCookie.setHttpOnly(true);  // JavaScript 无法访问
                accessTokenCookie.setSecure(false);    // 开发环境用 false，生产环境改为 true（需要 HTTPS）
                accessTokenCookie.setPath("/");
                accessTokenCookie.setMaxAge(3600);     // 1 小时
                // accessTokenCookie.setAttribute("SameSite", "Strict"); // Spring Boot 2.6+ 支持
                response.addCookie(accessTokenCookie);

                // 设置 ID Token 为 HttpOnly Cookie（如果存在）
                if (tokenResponse.getIdToken() != null && !tokenResponse.getIdToken().isEmpty()) {
                    Cookie idTokenCookie = new Cookie("id_token", tokenResponse.getIdToken());
                    idTokenCookie.setHttpOnly(true);
                    idTokenCookie.setSecure(false);
                    idTokenCookie.setPath("/");
                    idTokenCookie.setMaxAge(3600);
                    response.addCookie(idTokenCookie);
                }

                // 设置用户名为普通 Cookie（前端需要显示）
                Cookie usernameCookie = new Cookie("username", tokenResponse.getUsername());
                usernameCookie.setHttpOnly(false);  // 允许 JavaScript 读取
                usernameCookie.setSecure(false);
                usernameCookie.setPath("/");
                usernameCookie.setMaxAge(3600);
                response.addCookie(usernameCookie);

                log.info("✓ Tokens stored in HttpOnly cookies");

                // 重定向到前端 callback 页面（只传递 state，不传递 Token）
                String frontendUrl = String.format(
                    "http://localhost:5173/callback?state=%s",
                    state
                );

                return "redirect:" + frontendUrl;
            } else {
                log.error("✗ Token exchange failed");
                return "redirect:http://localhost:5173/?error=token_exchange_failed";
            }
        } catch (Exception e) {
            log.error("Error during callback processing", e);
            return "redirect:http://localhost:5173/?error=internal_error";
        }
    }
}
