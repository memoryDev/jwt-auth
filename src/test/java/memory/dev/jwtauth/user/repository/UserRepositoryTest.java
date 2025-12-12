package memory.dev.jwtauth.user.repository;

import memory.dev.jwtauth.user.domain.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void userId로유저를조회한다() {
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder passwordEncoder =
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();

        // given
        String userId = "test1";
        String rawPassword = "1234";
        String encodedPassword = passwordEncoder.encode(rawPassword);
        String userName = "테스트1";
        String role = "ROLE_USER";

        User user = User.builder()
                .userId(userId)
                .password(encodedPassword)
                .userName(userName)
                .role(role)
                .build();

        User savedUser = userRepository.save(user);

        //when userId로 조회
        Optional<User> resultUser = userRepository.findByUserId(userId);

        Assertions.assertTrue(resultUser.isPresent());

        User selectUser = resultUser.get();
        Assertions.assertEquals(savedUser.getUserId(), selectUser.getUserId());
        Assertions.assertEquals(savedUser.getPassword(), selectUser.getPassword());
        Assertions.assertTrue(passwordEncoder.matches(rawPassword, selectUser.getPassword()));
    }

    @Test
    void 회원가입() {
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder passwordEncoder =
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();

        String userId = "test2";
        String password = "1234";
        String userName = "테스트2";
        String role = "ROLE_USER";

        User user = User.builder()
                .userId(userId)
                .password(passwordEncoder.encode(password))
                .userName(userName)
                .role(role)
                .build();

        // when
        User savedUser = userRepository.save(user);

        // then
        Assertions.assertEquals(userId, savedUser.getUserId());
        Assertions.assertTrue(passwordEncoder.matches(password, savedUser.getPassword()));
        Assertions.assertEquals(role, savedUser.getRole());
    }

}