package memory.dev.jwtauth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import memory.dev.jwtauth.user.controller.CustomUserDetailService;
import memory.dev.jwtauth.user.domain.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.net.Authenticator;
import java.security.Key;
import java.util.Date;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    private final CustomUserDetailService userDetailService;

    private final long validityInMs = 1000L * 60 * 60; // 1시간

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC256(secretKey);
    }

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

    public String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

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

    public String getUserId(String token) {

        DecodedJWT decoded = getDecoded(token);

        return decoded.getSubject();

    }

    public Authentication getAuthentication(String token) {
        String userId = getUserId(token);
        UserDetails userDetails = userDetailService.loadUserByUsername(userId);
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    private DecodedJWT getDecoded(String token) {
        JWTVerifier verifier = JWT.require(getAlgorithm())
                .build();

        return verifier.verify(token);
    }
}
