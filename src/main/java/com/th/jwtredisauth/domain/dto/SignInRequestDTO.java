package com.th.jwtredisauth.domain.dto;


import lombok.Data;

@Data
public class SignInRequestDTO {
    private String email;
    private String password;
}
