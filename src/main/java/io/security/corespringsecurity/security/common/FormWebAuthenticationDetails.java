package io.security.corespringsecurity.security.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * WebAuthenticationDetails 를 상속한 클래스
 */
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretkey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.secretkey = request.getParameter("secret_key");
    }

    public String getSecretkey() {
        return secretkey;
    }
}
