package kz.edu.securecloud.web;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public record ShareRequest(@NotBlank @Size(max = 100) String ownerId, @NotBlank @Size(max = 100) String recipientId,
		@NotNull @Future Instant expiresAt) {
}
