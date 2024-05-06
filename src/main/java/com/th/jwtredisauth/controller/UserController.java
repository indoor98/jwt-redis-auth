package com.th.jwtredisauth.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.th.jwtredisauth.domain.dto.*;
import com.th.jwtredisauth.service.UserService;
import com.th.jwtredisauth.util.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
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
    public String test(HttpServletRequest request) throws JsonProcessingException {
        String rtk = request.getHeader("Authorization").substring(7);
        Subject subject = jwtProvider.getSubject(rtk);
        System.out.println(subject.getAuthorities());
        System.out.println(subject.getEmail());
        return "Hello!";
    }

    @GetMapping("/renew")
    public ResponseEntity<TokenResponseDTO> renew(HttpServletRequest request) throws JsonProcessingException {
        String rtk = request.getHeader("Authorization").substring(7);
        TokenResponseDTO response = jwtProvider.renewToken(rtk);
        return new  ResponseEntity<TokenResponseDTO>(response, HttpStatus.OK);
    }
}
