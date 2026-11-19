package kz.edu.securecloud.storage;

import java.util.UUID;

public interface StorageService {

    void save(UUID fileId, int version, byte[] encryptedContent);

    byte[] load(UUID fileId, int version);

    void delete(UUID fileId, int version);
}
