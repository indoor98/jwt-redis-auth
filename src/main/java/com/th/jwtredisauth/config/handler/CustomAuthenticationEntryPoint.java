package com.th.jwtredisauth.config.handler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.th.jwtredisauth.config.helper.Message;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;


/**
 * 토큰 관련 예외처리를 위한 핸들러????
 *
 */
@Component
@Getter
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public CustomAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authenticationException) throws IOException {
        String exceptionMessage = (String) request.getAttribute("exception");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        Message message = new Message(exceptionMessage, HttpStatus.UNAUTHORIZED);
        String res = this.convertObjectToJson(message);
        response.getWriter().print(res);
    }
    private String convertObjectToJson(Object object) throws JsonProcessingException {
        return object == null ? null : objectMapper.writeValueAsString(object);
    }
}
