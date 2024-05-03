package com.th.jwtredisauth.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.th.jwtredisauth.domain.dto.SignInRequestDTO;
import com.th.jwtredisauth.domain.dto.SignUpRequestDTO;
import com.th.jwtredisauth.domain.dto.TokenResponseDTO;
import com.th.jwtredisauth.domain.dto.UserResponseDTO;
import com.th.jwtredisauth.service.UserService;
import com.th.jwtredisauth.util.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {

    private final UserService userService;
    private final JwtProvider jwtProvider;

    @PostMapping("/signup")
    public ResponseEntity<UserResponseDTO> signUp(@RequestBody SignUpRequestDTO requestDTO) {
        UserResponseDTO responseDTO = userService.signUp(requestDTO);
        return new ResponseEntity<UserResponseDTO>(responseDTO, HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<TokenResponseDTO> signIn(@RequestBody SignInRequestDTO requestDTO) throws
            JsonProcessingException {
        UserResponseDTO userResponse = userService.signIn(requestDTO);
        TokenResponseDTO tokenResponseDTO = jwtProvider.createTokensBySignIn(userResponse);

        return new ResponseEntity<TokenResponseDTO>(tokenResponseDTO, HttpStatus.OK);
    }

    @GetMapping("/test")
    public String test() {
        return "Hello!";
    }
}
