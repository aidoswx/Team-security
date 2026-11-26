package kz.edu.securecloud.concurrent;
import java.util.*;
import java.util.concurrent.*;
import jakarta.annotation.PreDestroy;
import kz.edu.securecloud.crypto.EncryptionService;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.storage.StorageService;
import org.springframework.stereotype.Service;
@Service
public class IntegrityScanner implements AutoCloseable {
	private final StorageService storage;
	private final EncryptionService crypto;
	private final ExecutorService pool = new ThreadPoolExecutor(2, 4, 30, TimeUnit.SECONDS,
			new ArrayBlockingQueue<>(32), new ThreadPoolExecutor.CallerRunsPolicy());
	public IntegrityScanner(StorageService storage, EncryptionService crypto) {
		this.storage = storage;
		this.crypto = crypto;
	}
	public List<Result> scan(List<StoredFile> files) {
		List<CompletableFuture<Result>> jobs = files.stream()
				.map(f -> CompletableFuture.supplyAsync(() -> check(f), pool)).toList();
		return jobs.stream().map(CompletableFuture::join).toList();
	}
	private Result check(StoredFile f) {
		try {
			return new Result(f.fileId(), f.version(),
					crypto.sha256Hex(storage.load(f.fileId(), f.version())).equals(f.encryptedSha256())
							? Status.OK
							: Status.MODIFIED);
		} catch (RuntimeException e) {
			return new Result(f.fileId(), f.version(), Status.UNREADABLE);
		}
	}
	@PreDestroy
	public void close() {
		pool.shutdown();
		try {
			if (!pool.awaitTermination(10, TimeUnit.SECONDS))
				pool.shutdownNow();
		} catch (InterruptedException e) {
			pool.shutdownNow();
			Thread.currentThread().interrupt();
		}
	}
	public enum Status {
		OK, MODIFIED, UNREADABLE
	}
	public record Result(UUID fileId, int version, Status status) {
	}
}