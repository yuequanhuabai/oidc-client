package com.oidc.client.service;

import com.oidc.client.dto.TokenResponse;
import com.oidc.client.util.JwtTokenValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class OidcClientService {

    private final JwtTokenValidator jwtTokenValidator;
    private final RestTemplate restTemplate;
    private final String oidcServerUrl;
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;

    public OidcClientService(
            JwtTokenValidator jwtTokenValidator,
            RestTemplate restTemplate,
            @Value("${oidc.server.url:http://localhost:8080}") String oidcServerUrl,
            @Value("${oidc.server.token-endpoint:/oidc/token}") String tokenEndpoint,
            @Value("${oidc.client.id:my-app}") String clientId,
            @Value("${oidc.client.secret:secret123}") String clientSecret,
            @Value("${oidc.client.redirect-uri:http://localhost:8081/callback}") String redirectUri) {
        this.jwtTokenValidator = jwtTokenValidator;
        this.restTemplate = restTemplate;
        this.oidcServerUrl = oidcServerUrl;
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    public TokenResponse exchangeCodeForToken(String code) {
        try {
            String tokenUrl = oidcServerUrl + tokenEndpoint;

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "authorization_code");
            params.put("code", code);
            params.put("redirect_uri", redirectUri);
            params.put("client_id", clientId);
            params.put("client_secret", clientSecret);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            StringBuilder body = new StringBuilder();
            params.forEach((key, value) -> {
                if (body.length() > 0) body.append("&");
                body.append(key).append("=").append(value);
            });

            HttpEntity<String> request = new HttpEntity<>(body.toString(), headers);

            org.springframework.http.ResponseEntity<TokenResponse> response = restTemplate.postForEntity(
                    tokenUrl,
                    request,
                    TokenResponse.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                TokenResponse tokenResponse = response.getBody();

                // 从 access token 中提取用户名
                if (tokenResponse.getAccessToken() != null) {
                    String username = jwtTokenValidator.getUsernameFromToken(tokenResponse.getAccessToken());
                    tokenResponse.setUsername(username);
                }

                log.info("✓ Successfully exchanged code for token");
                return tokenResponse;
            } else {
                log.error("✗ Failed to exchange code: {}", response.getStatusCode());
                return null;
            }
        } catch (Exception e) {
            log.error("✗ Error exchanging code for token: {}", e.getMessage());
            return null;
        }
    }

    public boolean validateToken(String token) {
        return jwtTokenValidator.validateToken(token);
    }

    public String getUsernameFromToken(String token) {
        return jwtTokenValidator.getUsernameFromToken(token);
    }

    public Long getUserIdFromToken(String token) {
        return jwtTokenValidator.getUserIdFromToken(token);
    }
}
