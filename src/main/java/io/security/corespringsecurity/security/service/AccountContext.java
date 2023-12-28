package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domin.account.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * 시큐리티에서 제공하는 User 상속
 */
public class AccountContext extends User {
    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);

        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
