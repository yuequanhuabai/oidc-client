package com.oidc.client.controller;

import com.oidc.client.dto.TokenResponse;
import com.oidc.client.service.OidcClientService;
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
                                  @RequestParam(required = false) String state) {
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

                // 重定向到前端 callback 页面，使用 hash fragment 传递 token 和 state（不会发送到服务器）
                // 包含 state 参数让前端进行验证
                String frontendUrl = String.format(
                    "http://localhost:5173/callback#access_token=%s&id_token=%s&username=%s&state=%s",
                    tokenResponse.getAccessToken(),
                    tokenResponse.getIdToken() != null ? tokenResponse.getIdToken() : "",
                    tokenResponse.getUsername(),
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
