package kz.edu.securecloud.service;

import java.util.Objects;
import kz.edu.securecloud.domain.StoredFile;

public record FileDownload(StoredFile metadata, byte[] encryptedContent) {
    public FileDownload {
        Objects.requireNonNull(metadata, "metadata must not be null");
        Objects.requireNonNull(encryptedContent, "encryptedContent must not be null");
        encryptedContent = encryptedContent.clone();
    }

    @Override
    public byte[] encryptedContent() {
        return encryptedContent.clone();
    }
}
