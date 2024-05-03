package com.th.jwtredisauth.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.th.jwtredisauth.domain.dto.Subject;
import com.th.jwtredisauth.domain.dto.TokenResponseDTO;
import com.th.jwtredisauth.domain.dto.UserResponseDTO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final ObjectMapper objectMapper;

    @Value("${spring.jwt.key}")
    private String key;

    @Value("${spring.jwt.live.atk}")
    private Long atkLive;


    public TokenResponseDTO createTokensBySignIn(UserResponseDTO userResponseDTO) throws JsonProcessingException {
        Subject atkSubject = Subject.atk(userResponseDTO.getId(), userResponseDTO.getEmail(), userResponseDTO.getAuthorities());
        String atk = createToken(atkSubject, atkLive);
        return new TokenResponseDTO(atk, null);
    }
    
    // 토큰 생성 로직
    private String createToken(Subject subject, Long tokenLive) throws JsonProcessingException {
        SecretKey secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
        String subjectStr = objectMapper.writeValueAsString(subject);
        Claims claims = Jwts.claims()
                .setSubject(subjectStr);
        Date date = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(date)
                .setExpiration(new Date(date.getTime() + tokenLive))
                .signWith(secretKey)
                .compact();
    }

    // 토큰에 담긴 유저 정보(Subject)를 추출하는 함수
    public Subject getSubject(String atk) throws JsonProcessingException{
        SecretKey secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
        String subjectStr = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJwt(atk)
                .getBody()
                .getSubject();
        return objectMapper.readValue(subjectStr, Subject.class);
    }
}
