package memory.dev.jwtauth.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import memory.dev.jwtauth.auth.dto.LoginRequest;
import memory.dev.jwtauth.auth.dto.TokenResponse;
import memory.dev.jwtauth.user.domain.User;
import memory.dev.jwtauth.user.repository.UserRepository;
import memory.dev.jwtauth.util.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
                .orElseThrow(() -> new RuntimeException("등록되지 않은 사용자입니다.") );

        // 2. 비밀번호 검증
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("비밀번호가 존재하지 않습니다.");
        }

        // 3. 토큰 생성후 반환
        String accressToken = jwtTokenProvider.createToken(user);
        return TokenResponse.builder().accessToken(accressToken).build();
    }
}
