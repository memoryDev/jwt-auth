package memory.dev.jwtauth.config;

import lombok.RequiredArgsConstructor;
import memory.dev.jwtauth.filter.JwtAuthenticationFilter;
import memory.dev.jwtauth.user.controller.CustomUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // 설정 클래스
@EnableWebSecurity // Spring Security 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    // JWT 토큰을 검증해서 인증 정보를 SecurityContext에 넣어주는 필터
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // DB에서 유저 정보를 가져와 UserDetails로 변환하는 서비스
    private final CustomUserDetailService userDetailService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http

                // CSRF 비활성화 (JWT 사용시 주로 비활성화)
                .csrf(AbstractHttpConfigurer::disable)

                // 세션을 사용하지 않고, 각 요청을 독립적으로 처리 (JWT 기반)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // URL 별 인가(접근 권한) 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/api/login", "/api/signup"
                        , "/css/**", "/js/**", "/images/**")
                        .permitAll()
                        // 나머지 모든 요청은 인증 필요
                        .anyRequest().authenticated()

                )

                // 인증 시 사용할 UserDetailsService 지정
                .userDetailsService(userDetailService)

                // 기본 폼 로그인 비활성화(API 사용시)
                .formLogin(AbstractHttpConfigurer::disable)

                // 기본 HTTP Basic 인증 비활성화
                .httpBasic(AbstractHttpConfigurer::disable);

        http
                // UsernamePasswordAuthenticationFilter 전에 JWT 필터를 태움
                // 요청 들어올 때 먼저 JWT 검사해서 SecurityContext 채워줌
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class);

        // SecurityFilterChain 반환
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
