package com.nexus.api_gateway.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Configuration
public class CorsResponseHeaderSanitizerConfig {

    @Bean
    public GlobalFilter corsResponseHeaderSanitizer() {
        return (exchange, chain) -> chain.filter(exchange).then(Mono.fromRunnable(() -> sanitizeCorsHeaders(exchange)));
    }

    private void sanitizeCorsHeaders(ServerWebExchange exchange) {
        HttpHeaders headers = exchange.getResponse().getHeaders();

        // If both specific origin and '*' are present, retain the specific origin and remove '*'
        List<String> allowOrigin = headers.get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
        if (allowOrigin != null && allowOrigin.size() > 1) {
            // Prefer the first non-wildcard origin
            String preferred = allowOrigin.stream()
                    .filter(v -> v != null && !v.trim().equals("*"))
                    .findFirst()
                    .orElse(null);
            if (preferred != null) {
                headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, preferred);
            } else {
                // If only '*' exists, leave one '*' (no credentials should be used in that case)
                headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            }
        }

        // If Allow-Credentials is true, ensure ACAO is not '*'
        List<String> allowCreds = headers.get(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);
        if (allowCreds != null && allowCreds.stream().anyMatch("true"::equalsIgnoreCase)) {
            String currentOrigin = headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
            if ("*".equals(currentOrigin)) {
                // Try to use request Origin header as ACAO when available
                String requestOrigin = exchange.getRequest().getHeaders().getOrigin();
                if (requestOrigin != null && !requestOrigin.isBlank()) {
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, requestOrigin);
                }
            }
        }
    }
}

