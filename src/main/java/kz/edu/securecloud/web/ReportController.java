package kz.edu.securecloud.web;
import java.util.List;
import kz.edu.securecloud.report.ReportService;
import kz.edu.securecloud.concurrent.IntegrityScanner;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/reports")
public class ReportController {
	private final ReportService reports;
	private final IntegrityScanner scanner;
	public ReportController(ReportService reports, IntegrityScanner scanner) {
		this.reports = reports;
		this.scanner = scanner;
	}
	@GetMapping
	public ReportService.Summary summary(@RequestParam String ownerId) {
		Identity.require(ownerId);
		return reports.summarize(ownerId);
	}
	@GetMapping(value = "/csv", produces = "text/csv")
	public ResponseEntity<byte[]> csv(@RequestParam String ownerId) {
		Identity.require(ownerId);
		return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=report.csv")
				.contentType(MediaType.parseMediaType("text/csv;charset=UTF-8")).body(reports.csv(ownerId));
	}
	@PostMapping("/integrity")
	public List<IntegrityScanner.Result> integrity(@RequestParam String ownerId) {
		Identity.require(ownerId);
		return scanner.scan(reports.owned(ownerId));
	}
}
