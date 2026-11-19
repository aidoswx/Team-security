package kz.edu.securecloud.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record StoredFile(
        UUID fileId,
        int version,
        String ownerId,
        String originalFileName,
        String encryptedSha256,
        long encryptedSize,
        Instant createdAt
) {
    public StoredFile {
        Objects.requireNonNull(fileId, "fileId must not be null");
        Objects.requireNonNull(ownerId, "ownerId must not be null");
        Objects.requireNonNull(originalFileName, "originalFileName must not be null");
        Objects.requireNonNull(encryptedSha256, "encryptedSha256 must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        if (version < 1) {
            throw new IllegalArgumentException("Version must be positive");
        }
        if (encryptedSize < 1) {
            throw new IllegalArgumentException("Encrypted file must not be empty");
        }
    }
}
