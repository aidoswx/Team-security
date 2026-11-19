package kz.edu.securecloud.service;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import kz.edu.securecloud.domain.AccessGrant;
import org.springframework.stereotype.Service;

@Service
public class SharingService {

    private final ConcurrentMap<GrantKey, AccessGrant> grants = new ConcurrentHashMap<>();
    private final Clock clock;

    public SharingService(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    public AccessGrant grantAccess(
            UUID fileId, String ownerId, String recipientId, Instant expiresAt) {
        requireIdentifier(ownerId, "ownerId");
        requireIdentifier(recipientId, "recipientId");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        if (ownerId.equals(recipientId)) {
            throw new IllegalArgumentException("Owner already has access");
        }
        if (!expiresAt.isAfter(clock.instant())) {
            throw new IllegalArgumentException("Expiration time must be in the future");
        }

        AccessGrant grant = new AccessGrant(fileId, ownerId, recipientId, expiresAt);
        grants.put(new GrantKey(fileId, recipientId), grant);
        return grant;
    }

    public void revokeAccess(UUID fileId, String ownerId, String recipientId) {
        requireIdentifier(ownerId, "ownerId");
        requireIdentifier(recipientId, "recipientId");
        GrantKey key = new GrantKey(fileId, recipientId);
        grants.computeIfPresent(key, (ignored, grant) -> {
            if (!grant.ownerId().equals(ownerId)) {
                throw new SecurityException("Only the file owner can revoke access");
            }
            return null;
        });
    }

    public boolean hasAccess(UUID fileId, String ownerId, String requesterId) {
        requireIdentifier(ownerId, "ownerId");
        requireIdentifier(requesterId, "requesterId");
        if (ownerId.equals(requesterId)) {
            return true;
        }
        AccessGrant grant = grants.get(new GrantKey(fileId, requesterId));
        return grant != null && grant.ownerId().equals(ownerId) && grant.isActive(clock);
    }

    private static void requireIdentifier(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 100) {
            throw new IllegalArgumentException(name + " must contain 1 to 100 characters");
        }
    }

    private record GrantKey(UUID fileId, String recipientId) {
        private GrantKey {
            Objects.requireNonNull(fileId, "fileId must not be null");
            Objects.requireNonNull(recipientId, "recipientId must not be null");
        }
    }
}
