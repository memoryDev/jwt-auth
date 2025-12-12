package memory.dev.jwtauth.global.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
/**
 * @RestController에서 발생하는 예외들을 가로채서 공통으로 처리해 주는 어드바이스 클래스
 * -> 컨트롤마다 try-catch 안 쓰고, 여기서 한번에 예외 응답 형식을 맞출 수 있음
 */
public class GlobalExceptionHandler {

    // 1. 비즈니스 예외 처리 핸들러
    // BussinessException 이 던져졌을 때 이 메서드가 자동으로 호출됨
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorResponse> handleBusinessException(BusinessException e) {

        // 예외 안에 들어있는 ErrorCode 추출
        // ErrorCode에는 HttpStatus, message error message 저장되어있음
        ErrorCode code = e.getErrorCode();

        log.warn("Business exception: {}", code.name(), e);

        // 화면에 내려 줄 공통 에러 응답 바디 생성
        // ErrorResponse는 커스텀 응답 DTO(code / message /status
        ErrorResponse body = ErrorResponse.builder()
                .code(code.name())
                .message(code.getMessage())
                .status(code.getStatus().value())
                .build();

        return ResponseEntity
                .status(body.getStatus())
                .body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception e) {

        ErrorCode code = ErrorCode.INTERNAL_SERVER_ERROR;

        log.error("Unexpected exception", e);

        ErrorResponse body = ErrorResponse.builder()
                .status(code.getStatus().value())
                .code(code.name())
                .message(code.getMessage())
                .build();

        return ResponseEntity
                .status(body.getStatus())
                .body(body);
    }

}
