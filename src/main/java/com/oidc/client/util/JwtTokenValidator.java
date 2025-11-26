package com.oidc.client.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
@Slf4j
public class JwtTokenValidator {

    @Value("${jwt.secret:this-is-a-very-secret-key-that-should-be-at-least-256-bits-long-for-hs256-algorithm}")
    private String jwtSecret;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public Claims validateAndGetClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (SecurityException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return null;
    }

    public boolean validateToken(String token) {
        return validateAndGetClaims(token) != null;
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = validateAndGetClaims(token);
        if (claims == null) {
            return null;
        }
        return Long.parseLong(claims.get("sub").toString());
    }

    public String getUsernameFromToken(String token) {
        Claims claims = validateAndGetClaims(token);
        if (claims == null) {
            return null;
        }
        return claims.getSubject();
    }

    public String getClientIdFromToken(String token) {
        Claims claims = validateAndGetClaims(token);
        if (claims == null) {
            return null;
        }
        return (String) claims.get("client_id");
    }
}
