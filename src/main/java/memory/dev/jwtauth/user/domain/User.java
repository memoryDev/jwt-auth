package memory.dev.jwtauth.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(comment = "유저 고유키")
    private Long id;

    @Column(unique = true, nullable = false, comment = "유저 아이디")
    private String userId;

    @Column(nullable = false, comment = "비밀번호")
    private String password;

    @Column(comment = "유저 이름")
    private String userName;

    @Column(nullable = false)
    private String role = "ROLE_USER";

    //테스트에서 사용할 생성자 역할
    @Builder
    private User(String userId, String password, String userName, String role) {
        this.userId = userId;
        this.password = password;
        this.userName = userName;
        this.role = role;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getUsername() {
        return userId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
