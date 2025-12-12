package memory.dev.jwtauth.auth.controller;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import memory.dev.jwtauth.auth.dto.LoginRequest;
import memory.dev.jwtauth.auth.dto.TokenResponse;
import memory.dev.jwtauth.auth.service.AuthService;
import memory.dev.jwtauth.filter.JwtAuthenticationFilter;
import memory.dev.jwtauth.global.error.ErrorCode;
import memory.dev.jwtauth.global.error.GlobalExceptionHandler;
import memory.dev.jwtauth.util.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

@WebMvcTest(AuthRestController.class) // 컨트롤러만 로드
@Import(GlobalExceptionHandler.class) // 글로벌 예외 핸들러 같이 사용
@AutoConfigureMockMvc(addFilters = false)
class AuthRestControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoBean
    AuthService authService;

    @MockitoBean
    JwtAuthenticationFilter jwtAuthenticationFilter;

    @MockitoBean
    JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() throws Exception {
        Mockito.doAnswer(invocationOnMock -> {
            HttpServletRequest request = invocationOnMock.getArgument(0);
            HttpServletResponse response = invocationOnMock.getArgument(1);
            FilterChain filterChain = invocationOnMock.getArgument(2);
            filterChain.doFilter(request, response);
            return null;

        }).when(jwtAuthenticationFilter).doFilter(
                Mockito.any(HttpServletRequest.class),
                Mockito.any(HttpServletResponse.class),
                Mockito.any(FilterChain.class)
        );
    }


    @Test
    void 로그인_성공_시_200_과_토큰_반환() throws Exception {
        LoginRequest request = new LoginRequest("test1", "1234");

        TokenResponse response = new TokenResponse("access-token");

        Mockito.when(authService.login(Mockito.any(LoginRequest.class)))
                .thenReturn(response);

        mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.accessToken").value("access-token"));
    }

    @Test
    void 아이디가_비어있을경우_예외_반환() throws Exception {
        LoginRequest request = new LoginRequest("", "1234");

        mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.code").value(ErrorCode.USER_ID_REQUIRED.toString()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value(ErrorCode.USER_ID_REQUIRED.getMessage()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.status").value(HttpStatus.BAD_REQUEST.value()));

        Mockito.verifyNoInteractions(authService);
        Mockito.verifyNoInteractions(jwtTokenProvider);
        Mockito.verifyNoInteractions(jwtAuthenticationFilter);
    }

    @Test
    void 비밀번호_비어있을경우_예외_반환() throws Exception{

        LoginRequest request = new LoginRequest("test1", null);

        mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(MockMvcResultMatchers.jsonPath("$.code").value(ErrorCode.USER_PASSWORD_REQUIRED.toString()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value(ErrorCode.USER_PASSWORD_REQUIRED.getMessage()))
                .andExpect(MockMvcResultMatchers.jsonPath("$.status").value(HttpStatus.BAD_REQUEST.value()));

        Mockito.verifyNoInteractions(authService);
        Mockito.verifyNoInteractions(jwtTokenProvider);
        Mockito.verifyNoInteractions(jwtAuthenticationFilter);
    }

}