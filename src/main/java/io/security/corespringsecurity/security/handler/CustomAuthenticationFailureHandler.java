package io.security.corespringsecurity.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Invalid Username of Password";

        if(exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username of Password";
        } else if(exception instanceof InsufficientAuthenticationException) {
            errorMessage = "Invalid secret Key";
        }

        setDefaultFailureUrl("/login?errors=true&exception=" + exception.getMessage());

        // 부모 클래스인 onAuthenticationFailure 위임
        super.onAuthenticationFailure(request, response, exception);

    }
}
