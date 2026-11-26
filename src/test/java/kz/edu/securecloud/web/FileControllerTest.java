package kz.edu.securecloud.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import kz.edu.securecloud.domain.AccessGrant;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.service.FileDownload;
import kz.edu.securecloud.service.FileService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockMultipartFile;

@org.springframework.security.test.context.support.WithMockUser(username = "alice")
@WebMvcTest(FileController.class)
@Import({kz.edu.securecloud.config.SecurityConfig.class, GlobalExceptionHandler.class,
		FileControllerTest.FixedClockConfiguration.class})
class FileControllerTest {

	private static final Instant NOW = Instant.parse("2026-11-19T12:00:00Z");
	private static final UUID FILE_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
	private static final String HASH = "a".repeat(64);

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private FileService fileService;

	@Test
	void validMultipartUploadReturnsCreatedMetadata() throws Exception {
		StoredFile stored = metadata();
		when(fileService.uploadEncrypted(any(), anyString(), anyString(), anyInt(), any(), anyString()))
				.thenReturn(stored);
		MockMultipartFile file = new MockMultipartFile("file", "report.scv", MediaType.APPLICATION_OCTET_STREAM_VALUE,
				new byte[]{1, 2});

		mockMvc.perform(multipart("/api/files").file(file).param("ownerId", "alice").param("fileName", "report.txt")
				.param("version", "1").param("sha256", HASH)).andExpect(status().isCreated())
				.andExpect(jsonPath("$.fileId").value(FILE_ID.toString())).andExpect(jsonPath("$.version").value(1));
	}

	@Test
	void malformedChecksumIsRejectedBeforeServiceCall() throws Exception {
		MockMultipartFile file = new MockMultipartFile("file", "report.scv", MediaType.APPLICATION_OCTET_STREAM_VALUE,
				new byte[]{1});

		mockMvc.perform(multipart("/api/files").file(file).param("ownerId", "alice").param("fileName", "report.txt")
				.param("version", "1").param("sha256", "not-a-hash")).andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
	}

	@Test
	void encryptedDownloadSetsSafeHeadersAndBody() throws Exception {
		byte[] encrypted = new byte[]{5, 6, 7};
		when(fileService.downloadEncrypted(FILE_ID, 1, "alice")).thenReturn(new FileDownload(metadata(), encrypted));

		mockMvc.perform(get("/api/files/{fileId}/versions/{version}", FILE_ID, 1).param("requesterId", "alice"))
				.andExpect(status().isOk()).andExpect(content().bytes(encrypted))
				.andExpect(header().string("X-Encrypted-SHA256", HASH))
				.andExpect(header().string("Content-Disposition", org.hamcrest.Matchers.containsString("attachment")));
	}

	@Test
	void shareEndpointReturnsCreatedGrant() throws Exception {
		Instant expiration = Instant.now().plusSeconds(3600);
		when(fileService.grantAccess(eq(FILE_ID), eq("alice"), eq("bob"), eq(expiration)))
				.thenReturn(new AccessGrant(FILE_ID, "alice", "bob", expiration));

		mockMvc.perform(post("/api/files/{fileId}/shares", FILE_ID).contentType(MediaType.APPLICATION_JSON).content("""
				{"ownerId":"alice","recipientId":"bob","expiresAt":"%s"}
				""".formatted(expiration))).andExpect(status().isCreated())
				.andExpect(jsonPath("$.recipientId").value("bob"));
	}

	@Test
	void pastShareExpirationIsRejected() throws Exception {
		mockMvc.perform(post("/api/files/{fileId}/shares", FILE_ID).contentType(MediaType.APPLICATION_JSON).content("""
				{"ownerId":"alice","recipientId":"bob","expiresAt":"2020-01-01T00:00:00Z"}
				""")).andExpect(status().isBadRequest());
	}

	private static StoredFile metadata() {
		return new StoredFile(FILE_ID, 1, "alice", "report.txt", HASH, 3, NOW);
	}

	@TestConfiguration
	static class FixedClockConfiguration {
		@Bean
		Clock clock() {
			return Clock.fixed(NOW, ZoneOffset.UTC);
		}
	}
}
