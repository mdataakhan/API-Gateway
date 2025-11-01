package com.nexus.api_gateway.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.security.Key;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${jwt.algorithm:HS256}")
    private String algorithm;

    @Value("${jwt.secret:}")
    private String secret;

    @Value("${jwt.public-key:}")
    private String publicKeyPem;

    private Key signingKey; // for HMAC
    private PublicKey rsaPublicKey; // for RSA

    @PostConstruct
    public void init() throws Exception {
        if ("RS256".equalsIgnoreCase(algorithm)) {
            if (publicKeyPem == null || publicKeyPem.isBlank()) {
                throw new IllegalStateException("RS256 selected but jwt.public-key not configured");
            }
            // Remove PEM headers & decode
            String pem = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+","");
            byte[] decoded = Base64.getDecoder().decode(pem);
            java.security.spec.X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            rsaPublicKey = kf.generatePublic(spec);
        } else {
            // HS256 and others HMAC family
            if (secret == null || secret.isBlank()) {
                throw new IllegalStateException("HS256 selected but jwt.secret not configured");
            }
            // support if secret is base64
            byte[] keyBytes;
            if (isBase64(secret)) keyBytes = Decoders.BASE64.decode(secret);
            else keyBytes = secret.getBytes();
            signingKey = Keys.hmacShaKeyFor(keyBytes);
        }
    }

    public Jws<Claims> validateTokenAndGetClaims(String token) {
        try {
            JwtParserBuilder builder = Jwts.parserBuilder();
            if ("RS256".equalsIgnoreCase(algorithm)) {
                builder.setSigningKey(rsaPublicKey);
            } else {
                builder.setSigningKey(signingKey);
            }
            JwtParser parser = builder.build();
            return parser.parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            throw e;
        } catch (JwtException e) {
            throw e;
        }
    }

    private boolean isBase64(String s) {
        try {
            // crude check
            Base64.getDecoder().decode(s);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /** helper to read a claim safely as String */
    public static String claimAsString(Claims claims, String name) {
        Object val = claims.get(name);
        return val == null ? null : String.valueOf(val);
    }

    /** helper to return map of selected claims for header propagation */
    public static Map<String, Object> claimsToMap(Claims claims) {
        return Map.copyOf(claims);
    }
}
