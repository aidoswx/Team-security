package kz.edu.securecloud.report;
import java.util.*;
import java.util.stream.Collectors;
import java.nio.charset.StandardCharsets;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.repository.FileMetadataRepository;
import org.springframework.stereotype.Service;
@Service
public class ReportService {
	private final FileMetadataRepository repository;
	public ReportService(FileMetadataRepository repository) {
		this.repository = repository;
	}
	public List<StoredFile> owned(String owner) {
		return repository.findAll().stream().filter(f -> f.ownerId().equals(owner)).toList();
	}
	public Summary summarize(String owner) {
		List<StoredFile> files = owned(owner);
		Set<UUID> ids = files.stream().map(StoredFile::fileId).collect(Collectors.toSet());
		Map<String, Long> byExtension = files.stream().collect(
				Collectors.groupingBy(f -> extension(f.originalFileName()), TreeMap::new, Collectors.counting()));
		return new Summary(ids.size(), files.size(), files.stream().mapToLong(StoredFile::encryptedSize).sum(),
				byExtension);
	}
	public byte[] csv(String owner) {
		StringBuilder out = new StringBuilder("fileId,version,fileName,encryptedBytes,createdAt\r\n");
		owned(owner).forEach(f -> out.append(f.fileId()).append(',').append(f.version()).append(',')
				.append(cell(f.originalFileName())).append(',').append(f.encryptedSize()).append(',')
				.append(f.createdAt()).append("\r\n"));
		return out.toString().getBytes(StandardCharsets.UTF_8);
	}
	private static String cell(String value) {
		// Prevent spreadsheet formula execution and escape RFC 4180 quotes.
		if (!value.isEmpty() && "=+-@\t\r\n".indexOf(value.charAt(0)) >= 0)
			value = "'" + value;
		return "\"" + value.replace("\"", "" + "\"\"") + "\"";
	}
	private static String extension(String name) {
		int dot = name.lastIndexOf('.');
		return dot < 0 ? "(none)" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
	}
	public record Summary(int files, int versions, long encryptedBytes, Map<String, Long> byExtension) {
	}
}