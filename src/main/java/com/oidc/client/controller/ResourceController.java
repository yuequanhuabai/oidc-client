package com.oidc.client.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/resources")
@Slf4j
public class ResourceController {

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(HttpServletRequest request) {
        Long userId = (Long) request.getAttribute("userId");
        String username = (String) request.getAttribute("username");

        Map<String, Object> profile = new HashMap<>();
        profile.put("userId", userId);
        profile.put("username", username);
        profile.put("email", username + "@example.com");
        profile.put("role", "user");
        profile.put("createdAt", "2025-01-01T00:00:00Z");

        log.info("✓ User profile retrieved: {}", username);
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/data")
    public ResponseEntity<?> getData(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");

        Map<String, Object> data = new HashMap<>();
        data.put("message", "This is protected data for user: " + username);
        data.put("timestamp", System.currentTimeMillis());
        data.put("items", new String[]{"item1", "item2", "item3"});

        log.info("✓ Protected data retrieved by user: {}", username);
        return ResponseEntity.ok(data);
    }
}
