package kz.edu.securecloud.web;

import jakarta.validation.ConstraintViolationException;
import java.time.Clock;
import java.util.NoSuchElementException;
import kz.edu.securecloud.crypto.CryptoException;
import kz.edu.securecloud.storage.StorageException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	private final Clock clock;

	public GlobalExceptionHandler(Clock clock) {
		this.clock = clock;
	}

	@ExceptionHandler({IllegalArgumentException.class, CryptoException.class, ConstraintViolationException.class,
			MethodArgumentNotValidException.class})
	ResponseEntity<ApiError> badRequest(Exception exception) {
		return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", safeMessage(exception));
	}

	@ExceptionHandler(SecurityException.class)
	ResponseEntity<ApiError> forbidden(SecurityException exception) {
		return error(HttpStatus.FORBIDDEN, "ACCESS_DENIED", exception.getMessage());
	}

	@ExceptionHandler(NoSuchElementException.class)
	ResponseEntity<ApiError> notFound(NoSuchElementException exception) {
		return error(HttpStatus.NOT_FOUND, "NOT_FOUND", exception.getMessage());
	}

	@ExceptionHandler(IllegalStateException.class)
	ResponseEntity<ApiError> conflict(IllegalStateException exception) {
		return error(HttpStatus.CONFLICT, "CONFLICT", exception.getMessage());
	}

	@ExceptionHandler(MaxUploadSizeExceededException.class)
	ResponseEntity<ApiError> tooLarge(MaxUploadSizeExceededException exception) {
		return error(HttpStatus.PAYLOAD_TOO_LARGE, "FILE_TOO_LARGE", "Encrypted file exceeds 50 MB");
	}

	@ExceptionHandler(StorageException.class)
	ResponseEntity<ApiError> storageFailure(StorageException exception) {
		return error(HttpStatus.INTERNAL_SERVER_ERROR, "STORAGE_ERROR", "Encrypted storage operation failed");
	}

	private ResponseEntity<ApiError> error(HttpStatus status, String code, String message) {
		return ResponseEntity.status(status).body(new ApiError(clock.instant(), status.value(), code, message));
	}

	private static String safeMessage(Exception exception) {
		if (exception instanceof MethodArgumentNotValidException) {
			return "Request validation failed";
		}
		String message = exception.getMessage();
		return message == null || message.isBlank() ? "Request validation failed" : message;
	}
}
