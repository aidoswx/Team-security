package kz.edu.securecloud.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import kz.edu.securecloud.domain.AccessGrant;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.service.FileDownload;
import kz.edu.securecloud.service.FileService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@Validated
@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<StoredFile> upload(
            @RequestParam(required = false) UUID fileId,
            @RequestParam @NotBlank @Size(max = 100) String ownerId,
            @RequestParam @NotBlank @Size(max = 255) String fileName,
            @RequestParam @Min(1) @Max(1_000_000) int version,
            @RequestParam @Pattern(regexp = "(?i)[0-9a-f]{64}") String sha256,
            @RequestPart("file") MultipartFile file) throws IOException {
        StoredFile storedFile = fileService.uploadEncrypted(
                fileId, ownerId, fileName, version, file.getBytes(), sha256);
        return ResponseEntity.status(201).body(storedFile);
    }

    @GetMapping("/{fileId}/versions")
    public List<StoredFile> listVersions(
            @PathVariable UUID fileId,
            @RequestParam @NotBlank @Size(max = 100) String requesterId) {
        return fileService.listVersions(fileId, requesterId);
    }

    @GetMapping("/{fileId}/versions/{version}")
    public ResponseEntity<byte[]> download(
            @PathVariable UUID fileId,
            @PathVariable @Min(1) int version,
            @RequestParam @NotBlank @Size(max = 100) String requesterId) {
        FileDownload download = fileService.downloadEncrypted(fileId, version, requesterId);
        ContentDisposition disposition = ContentDisposition.attachment()
                .filename(download.metadata().originalFileName() + ".scv", StandardCharsets.UTF_8)
                .build();
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(download.encryptedContent().length)
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .header("X-Encrypted-SHA256", download.metadata().encryptedSha256())
                .body(download.encryptedContent());
    }

    @PostMapping("/{fileId}/shares")
    public ResponseEntity<AccessGrant> share(
            @PathVariable UUID fileId,
            @Valid @RequestBody ShareRequest request) {
        AccessGrant grant = fileService.grantAccess(
                fileId, request.ownerId(), request.recipientId(), request.expiresAt());
        return ResponseEntity.status(201).body(grant);
    }

    @DeleteMapping("/{fileId}/shares")
    public ResponseEntity<Void> revoke(
            @PathVariable UUID fileId,
            @RequestParam @NotBlank @Size(max = 100) String ownerId,
            @RequestParam @NotBlank @Size(max = 100) String recipientId) {
        fileService.revokeAccess(fileId, ownerId, recipientId);
        return ResponseEntity.noContent().build();
    }
}
