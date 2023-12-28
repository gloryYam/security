package io.security.corespringsecurity.sevice;

import io.security.corespringsecurity.domin.account.entity.Account;

public interface UserService {

    void createUser(Account account);
}
