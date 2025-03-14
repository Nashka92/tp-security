package com.m2ibank.config.jwt;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;


import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        // Lorsque l'authentification échoue, cette méthode est appelée.

        // Envoi d'une réponse d'erreur au client.
        // HttpServletResponse.SC_UNAUTHORIZED est l'équivalent numérique de 401,
        // ce qui indique que la demande nécessite une authentification valide.
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
