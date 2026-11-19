package kz.edu.securecloud.web;

import java.time.Instant;

public record ApiError(Instant timestamp, int status, String code, String message) {
}
