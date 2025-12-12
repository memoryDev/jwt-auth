package memory.dev.jwtauth.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import memory.dev.jwtauth.auth.dto.LoginRequest;
import memory.dev.jwtauth.auth.dto.TokenResponse;
import memory.dev.jwtauth.global.error.BusinessException;
import memory.dev.jwtauth.global.error.ErrorCode;
import memory.dev.jwtauth.user.domain.User;
import memory.dev.jwtauth.user.repository.UserRepository;
import memory.dev.jwtauth.util.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.thymeleaf.util.StringUtils;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public TokenResponse login(LoginRequest request) {
        
        // 1. 유저 정보 조회
        User user = userRepository.findByUserId(request.getUserId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        // 2. 비밀번호 검증
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BusinessException(ErrorCode.INVALID_PASSWORD);
        }

        // 3. 토큰 생성후 반환
        String accressToken = jwtTokenProvider.createToken(user);
        if (StringUtils.isEmpty(accressToken)) {
            throw new BusinessException(ErrorCode.TOKEN_GENERATION_FAILED);
        }

        return TokenResponse.builder().accessToken(accressToken).build();
    }
}
