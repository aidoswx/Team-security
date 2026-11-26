package kz.edu.securecloud.domain;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record AccessGrant(UUID fileId, String ownerId, String recipientId, Instant expiresAt) {
	public AccessGrant {
		Objects.requireNonNull(fileId, "fileId must not be null");
		Objects.requireNonNull(ownerId, "ownerId must not be null");
		Objects.requireNonNull(recipientId, "recipientId must not be null");
		Objects.requireNonNull(expiresAt, "expiresAt must not be null");
	}

	public AccessStatus status(Clock clock) {
		return expiresAt.isAfter(clock.instant()) ? AccessStatus.ACTIVE : AccessStatus.EXPIRED;
	}
	public boolean isActive(Clock clock) {
		return status(clock) == AccessStatus.ACTIVE;
	}
}
