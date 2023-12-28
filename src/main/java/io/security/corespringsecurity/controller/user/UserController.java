package io.security.corespringsecurity.controller.user;

import io.security.corespringsecurity.domin.account.dto.AccountDto;
import io.security.corespringsecurity.domin.account.entity.Account;
import io.security.corespringsecurity.sevice.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @GetMapping(value = "/mypage")
    public String myPage() throws Exception {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser(Model model) {

        model.addAttribute("accountDto", new AccountDto());

        return "user/login/register";
    }


    @PostMapping("/users")
    public String createUser(@Valid @ModelAttribute AccountDto accountDto, BindingResult result ) {

        if(result.hasErrors()) {
            StringBuilder sb = new StringBuilder();
            for (FieldError error : result.getFieldErrors()) {
                sb.append(error.getDefaultMessage());
            }
            return "user/login/register";
        }

        userService.createUser(accountDto.toEntity());

        return "redirect:/";
    }
}
