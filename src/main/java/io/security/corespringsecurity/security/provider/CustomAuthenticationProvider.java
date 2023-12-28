package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 검증을 위한 구현
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 여기서 authentication 은 AuthenticationManager 로 부터 전달 받은 인증 객체
        // 여기에는 사용자가 인증할 때 입력한 ID, Password 정보가 담겨져 있다.
        // 그래서 추출 가능
        String username = authentication.getName();                         // 아이디
        String password = (String) authentication.getCredentials();      // 비밀번호 Object -> String 타입캐스팅

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        /**
         * 패스워드 검증
         */
        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException(" BadCredentialsException ");
        }

        /**
         * 클라이언트가 전달하는 내용 중 secret 키가 포함되어 있는지
         */
        // 시크릿 키 인증
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretkey = formWebAuthenticationDetails.getSecretkey();

        if (secretkey == null || !"secret".equals(secretkey)) {

            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");

        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return authenticationToken;     // AuthenticationManager 에 리턴
    }

    /**
     *  Provider 가 사용하고자 하는 토큰의 타입이 일치할 때 인증 처리
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        // 토큰이 파라미터로 전달된 토큰타입과 일치하면 인증 처리하도록
    }
}
