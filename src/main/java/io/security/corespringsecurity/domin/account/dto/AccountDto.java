package io.security.corespringsecurity.domin.account.dto;

import io.security.corespringsecurity.domin.account.entity.Account;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.crypto.password.PasswordEncoder;

@Data
public class AccountDto {

    @NotEmpty(message = "이름은 필수입니다.")
    private String username;

    private String password;

    private String email;

    private String age;

    private String role;

    public Account toEntity() {
        return Account.builder()
                .username(username)
                .password(password)
                .email(email)
                .age(age)
                .role(role)
                .build();
    }
}
