package memory.dev.jwtauth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import memory.dev.jwtauth.user.service.CustomUserDetailService;
import memory.dev.jwtauth.user.domain.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    // DB에서 유저 정보를 가져오는 서비스
    private final CustomUserDetailService userDetailService;

    // 토큰 유효시간 (1시간)
    private final long validityInMs = 1000L * 60 * 60;

    // HMAC256 알고리즘 생성 (서명/검증에 사용)
    private Algorithm getAlgorithm() {
        return Algorithm.HMAC256(secretKey);
    }

    // User 정보로 JWT 토큰 생성
    public String createToken(User user) {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + validityInMs);

        return JWT.create()
                .withSubject(user.getUserId())
                .withClaim("userId", user.getUserId())
                .withClaim("role", user.getRole())
                .withIssuedAt(now)
                .withExpiresAt(expiry)
                .sign(this.getAlgorithm());
    }

    // HTTP 요청 헤더에서 토큰 추출
    public String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

    // 토큰의 유효성 검사(서명 + 만료시간 확인)
    public boolean validateToken(String token) {
        try {
            DecodedJWT decoded = getDecoded(token);

            Date expiresAt = decoded.getExpiresAt();
            return expiresAt == null || expiresAt.after(new Date());
        } catch (JWTVerificationException e) {
            log.warn("JWT 검증 실패: {}", e.getMessage());
            return false;
        }
    }

    // 토큰에서 UserId 추출
    public String getUserId(String token) {

        DecodedJWT decoded = getDecoded(token);

        return decoded.getSubject();

    }

    // 토큰으로부터 Authentication 객체 생성(SecurityContext에 넣을 용도)
    public Authentication getAuthentication(String token) {

        // 토큰에서 userId 조회
        String userId = getUserId(token);

        // DB에서 유저 정보 조회
        UserDetails userDetails = userDetailService.loadUserByUsername(userId);

        // 스프링 시큐리티에서 사용하는 인증 객체 생성
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    // 토큰을 검증하고 디코딩된 JWT 객체 반환
    private DecodedJWT getDecoded(String token) {
        JWTVerifier verifier = JWT.require(getAlgorithm())
                .build();

        return verifier.verify(token);
    }
}
