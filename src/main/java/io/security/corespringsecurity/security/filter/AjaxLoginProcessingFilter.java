package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domin.account.dto.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 필터 작동 조선
     * ("/api/login")로 요청 정보와 매칭, 요청 방식이 Ajax 이면 필터 작동
     */
    public AjaxLoginProcessingFilter() {

        // 이 url 로 요청을 했을 때 매칭이 되면 필터 작동
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        // Ajax 인지 아닌지 확인
        if(!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        // ( json 방식으로 오면 json -> 객체 추출 )
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalArgumentException("Username of Password is empty");
        }

        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        // 토큰을 인증 처리하는 getAuthenticationManager 에 전달
        return getAuthenticationManager().authenticate(authenticationToken);
    }

    /**
     * 사용자가 요청을 할 때 헤더에 정보를 담아서 보낸다.
     * 그 정보에 담긴 값과 같은지 안 같은지 (약속 정하기)
     */
    private boolean isAjax(HttpServletRequest request) {

        // 헤더명에 해당하는 값이 아래에 값과 일치할 때
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-with"))) {
            return true;
        }
        return false; // 아니면 false
    }
}
