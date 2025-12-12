package memory.dev.jwtauth.global.error;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ErrorResponse {
    private String code; // ex)USER_NOT_FOUND
    private String message; // ex) 존재하지 않는 회원입니다.
    private int status; // ex)404
}
