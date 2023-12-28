package io.security.corespringsecurity.sevice.impl;

import io.security.corespringsecurity.domin.account.entity.Account;
import io.security.corespringsecurity.repository.UserRepository;
import io.security.corespringsecurity.sevice.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    @Override
    public void createUser(Account account) {

        /**
         * password 평문 -> 암호화
         */
        String encodedPassword = passwordEncoder.encode(account.getPassword());
        account.Password(encodedPassword);

        userRepository.save(account);
    }
}
