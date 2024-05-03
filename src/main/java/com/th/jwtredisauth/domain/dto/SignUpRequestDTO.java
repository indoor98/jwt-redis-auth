package com.th.jwtredisauth.domain.dto;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Data
public class SignUpRequestDTO {
    private String email;
    private String password;
    private List<String> authorities;
}
