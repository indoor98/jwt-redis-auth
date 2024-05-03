package com.th.jwtredisauth.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenResponseDTO {

    private final String atk;

    private final String rtk;


}
