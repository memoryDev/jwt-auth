package memory.dev.jwtauth.auth.service;

import memory.dev.jwtauth.auth.dto.LoginRequest;
import memory.dev.jwtauth.auth.dto.TokenResponse;
import memory.dev.jwtauth.user.domain.User;
import memory.dev.jwtauth.user.repository.UserRepository;
import memory.dev.jwtauth.util.JwtTokenProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    /**
     * [Mock] : 실제 DB 대신 사용할 가짜 메서드  
     * [InjectMocks] : @Mock 들이 주입된 AuthService 테스트용 인스턴스
     */
    
    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    AuthService authService;

    @Test
    void 로그인하면_토큰_생성() {
        // given
        String userId = "test1"; // 로그인 시도할 아이디
        String rawPassword = "1234"; // 사용자가 입력한 비밀번호(압호화전)
        String encodedPassword = "$2b$12$fB6vqSY9ff8dPc6RSh32LO.uoDCGhgnTq0/xXZ5TRvlqqCeujXsMG"; // DB에 저장된 암호화된 비밀번호
        String userName = "test1"; // 유저 이름
        String role = "ROLE_USER"; // 유저 권한

        // DB에서 조회해 온 것처럼 사용할 가짜 user 엔티티
        User user = User.builder()
                .userId(userId)
                .password(encodedPassword)
                .userName("test1")
                .role("ROLE_USER")
                .build();

        // 강제로 userRepository.findByUserId(userId)가 호출되면 Optional.of(user)를 리턴하도록 설정
        Mockito.when(userRepository.findByUserId(userId))
        .thenReturn(Optional.of(user));

        // passwordEncoder.matches(입력비번, 저장비번)이 true를 리턴하도록 설정
        // => 비밀번호가 일치하는 정상 로그인 상황
        Mockito.when(passwordEncoder.matches(rawPassword, encodedPassword))
                .thenReturn(true);

        // jwtTokenProvider.createToken(user)가 호출되면 "access-token" 문자열을 리턴하도록 설정
        // => 실제 JWT를 만들지 않고, 토큰 생성 결과만 고정값으로 흉내냄
        Mockito.when(jwtTokenProvider.createToken(user))
                .thenReturn("access-token");

        // 컨트롤러에서 넘어온다고 가정하는 로그인 요청 DTO
        LoginRequest request = new LoginRequest(userId, rawPassword);

        // when
        TokenResponse response = authService.login(request);

        // 응답으로 넘어온 accessToken 이 우리가 mock에서 설정한 값과 같은지 확인
        Assertions.assertEquals("access-token", response.getAccessToken());

        // 로그인 과정에서  userRepository.findByUserId(user)가 한 번 호출되었는지 검증
        Mockito.verify(userRepository).findByUserId(userId);

        // 토큰 생성 과정에서 jwtTokenProvider.createToken(user)가 호출되었는지 검증
        Mockito.verify(jwtTokenProvider).createToken(user);
    }

    @Test
    void 아이디가_없으면_예외발생() {

        // given
        String userId = "noId"; // 로그인 시도할 잘못된 아이디
        String rawPassword = "1234"; // 로그인 시도할 비밀번호

        // userRepository.findByUserId(userId) 호출하면 빈값 리턴하도록 설정
        // => 해당 아이디로 저장된 유저가 없다는 상황
        Mockito.when(userRepository.findByUserId(userId))
                .thenReturn(Optional.empty());

        // 존재하지 않는 아이디로 로그인 요청 DTO 생성
        LoginRequest request = new LoginRequest(userId, rawPassword);

        // when authService.login(request) 요청시 아이디가 존재히지 않아 RuntimeException 발생 여부 확인
        RuntimeException runtimeException = assertThrows(
                RuntimeException.class,
                () -> authService.login(request)
        );

        // 로그인시 예외발생한 메세지로 예외 던지는지 체크
        Assertions.assertEquals("등록되지 않은 사용자입니다.", runtimeException.getMessage());

        // 아이디 조회는 시도해야 하므로, userRepository.findByUserId(userId) 호출했는지 검증
        Mockito.verify(userRepository).findByUserId(userId);

        // 아이디 자체가 없으므로, 토큰 생성 로직은 절대 호출되면 안됨, 호출했는지 검증
        Mockito.verify(jwtTokenProvider, Mockito.never())
                .createToken(Mockito.any(User.class));
    }

    @Test
    void 비밀번호가_다르면_예외발생() {

        // given
        String userId = "test1"; // 로그인 유저아이디
        String rawPassword = "12342"; // 잘못된 로그인 비밀번호
        String encodedPassword = "$2b$12$fB6vqSY9ff8dPc6RSh32LO.uoDCGhgnTq0/xXZ5TRvlqqCeujXsMG"; // DB에 저장된 암호화된 비밀번호

        String userName = "테스트1"; // 유저 이름
        String role = "ROLE_USER";  // 유저 권한

        // DB에서 조회해 온 것처럼 사용할 가짜 user 엔티티
        User user = User.builder()
                .userId(userId)
                .password(encodedPassword)
                .userName(userName)
                .role(role)
                .build();

        // userRepository.findByUserId(userId) 호출시 user 엔티티 응답하도록 설정
        Mockito.when(userRepository.findByUserId(userId))
                .thenReturn(Optional.of(user));

        // 로그인 요청시 사용할 DTO
        LoginRequest request = new LoginRequest(userId, rawPassword);

        // 로그인 요청시 비밀번호가 다르므로 Exception 발생했는지 검증
        RuntimeException runtimeException = assertThrows(
                RuntimeException.class,
                () -> authService.login(request)

        );

        // 로그인시 예외발생한 메세지로 예외 던지는지 체크
        Assertions.assertEquals("비밀번호가 존재하지 않습니다.", runtimeException.getMessage());

        // 비밀번호는 다르지만 회원정보 호출 했는지 검증
        Mockito.verify(userRepository).findByUserId(userId);
        
        // 비밀번호가 다르기 때문에 토큰 생성 로직은 호출 되면 안됨
        Mockito.verify(jwtTokenProvider, Mockito.never())
                .createToken(Mockito.any(User.class));
    }

}