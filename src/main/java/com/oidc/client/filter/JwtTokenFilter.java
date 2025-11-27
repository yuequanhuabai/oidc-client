package com.oidc.client.filter;

import com.oidc.client.util.JwtTokenValidator;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@AllArgsConstructor
@Slf4j
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // 跳过无需认证的端点
        if (path.equals("/api/auth/token") ||
            path.equals("/api/auth/health") ||
            path.equals("/api/health") ||
            path.equals("/callback") ||
            path.startsWith("/static/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            if (jwtTokenValidator.validateToken(token)) {
                String username = jwtTokenValidator.getUsernameFromToken(token);
                Long userId = jwtTokenValidator.getUserIdFromToken(token);

                request.setAttribute("userId", userId);
                request.setAttribute("username", username);

                log.debug("Token validated for user: {}", username);
                filterChain.doFilter(request, response);
                return;
            } else {
                log.warn("Invalid token provided");
            }
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Unauthorized\", \"message\": \"Missing or invalid token\"}");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.equals("/api/auth/token") ||
               path.equals("/api/health") ||
               path.equals("/callback") ||
               path.startsWith("/static/");
    }
}
