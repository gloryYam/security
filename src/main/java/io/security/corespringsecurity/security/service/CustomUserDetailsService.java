package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domin.account.entity.Account;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService")
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;    // 유저 데이터 정보를 얻기 위해

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = userRepository.findByUsername(username);  // username 찾고

        if(account == null) {
            throw new UsernameNotFoundException("UsernameNotFoundException");
        }

        /**
         * UserDetails 타입으로 반환해야 됨 UserDetailsService -> UserDetails
         * UserDetails 반환하기 위해 AccountContext 객체를 생성해서 반환
         */
        List<GrantedAuthority> roles = new ArrayList<>();

        // 권한 정보
        roles.add(new SimpleGrantedAuthority(account.getRole()));

        AccountContext accountContext = new AccountContext(account, roles);

        return accountContext;
    }
}
