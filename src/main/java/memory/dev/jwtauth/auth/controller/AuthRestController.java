package memory.dev.jwtauth.auth.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import memory.dev.jwtauth.auth.dto.LoginRequest;
import memory.dev.jwtauth.auth.dto.TokenResponse;
import memory.dev.jwtauth.auth.service.AuthService;
import memory.dev.jwtauth.global.error.BusinessException;
import memory.dev.jwtauth.global.error.ErrorCode;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Slf4j
public class AuthRestController {

    private final AuthService authService;

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {

        if(StringUtils.isEmpty(request.getUserId())) {
            throw new BusinessException(ErrorCode.USER_ID_REQUIRED);
        }

        if (StringUtils.isEmpty(request.getPassword())) {
            throw new BusinessException(ErrorCode.USER_PASSWORD_REQUIRED);
        }

        return authService.login(request);
    }

}
