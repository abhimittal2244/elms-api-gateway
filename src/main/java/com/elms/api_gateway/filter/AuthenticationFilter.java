package com.elms.api_gateway.filter;

import com.elms.api_gateway.util.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtService jwtService;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("Missing Authorization Header");
                }

                String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }

                try {
                    if(!jwtService.validateToken(authHeader))
                        throw  new RuntimeException("Provided token is invalid");
                    String userId = jwtService.extractUsername(authHeader);
                    String role = jwtService.extractRole(authHeader);

                    return chain.filter(exchange.mutate()
                            .request(r -> r.headers(headers -> {
                                headers.add("X-User-Id", userId);
                                headers.add("X-User-Roles", role);
                            }))
                            .build());

                } catch (Exception e) {
                    throw new RuntimeException("Unauthorized access to application");
                }
            }

            return chain.filter(exchange);
        };
    }

    public static class Config {

    }
}