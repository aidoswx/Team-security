package kz.edu.securecloud.web;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import kz.edu.securecloud.crypto.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.mock.web.MockMultipartFile;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest
@AutoConfigureMockMvc
class ApiIntegrationTest {
	static Path temp;
	static {
		try {
			temp = Files.createTempDirectory("securecloud-integration-");
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}
	@DynamicPropertySource
	static void paths(DynamicPropertyRegistry r) {
		r.add("secure-storage.root", () -> temp.resolve("encrypted").toString());
		r.add("secure-storage.database", () -> temp.resolve("test.db").toString());
	}
	@Autowired
	MockMvc mvc;
	@Autowired
	ObjectMapper json;
	@Test
	void requiresAuthentication() throws Exception {
		mvc.perform(get("/api/reports").param("ownerId", "alice")).andExpect(status().isUnauthorized());
	}
	@Test
	void rejectsImpersonation() throws Exception {
		mvc.perform(get("/api/reports").param("ownerId", "bob").with(httpBasic("alice", "test-alice-password")))
				.andExpect(status().isForbidden());
	}
	@Test
	void encryptedUploadDownloadReportAndScan() throws Exception {
		EncryptionService c = new EncryptionService();
		byte[] encoded = EncryptedFileCodec.encode(c.encrypt("secret".getBytes(),
				"long-encryption-password".toCharArray(), c.associatedData("alice", "report.txt", 1)));
		String body = mvc
				.perform(multipart("/api/files")
						.file(new MockMultipartFile("file", "report.scv", "application/octet-stream", encoded))
						.param("ownerId", "alice").param("fileName", "report.txt").param("version", "1")
						.param("sha256", c.sha256Hex(encoded)).with(httpBasic("alice", "test-alice-password")))
				.andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
		String id = json.readTree(body).get("fileId").asText();
		mvc.perform(get("/api/files/" + id + "/versions/1").param("requesterId", "alice")
				.with(httpBasic("alice", "test-alice-password"))).andExpect(status().isOk())
				.andExpect(content().bytes(encoded));
		mvc.perform(get("/api/files/" + id + "/versions/1").param("requesterId", "bob")
				.with(httpBasic("bob", "test-bob-password"))).andExpect(status().isForbidden());
		mvc.perform(get("/api/reports/csv").param("ownerId", "alice").with(httpBasic("alice", "test-alice-password")))
				.andExpect(status().isOk())
				.andExpect(content().string(org.hamcrest.Matchers.containsString("report.txt")));
		mvc.perform(post("/api/reports/integrity").param("ownerId", "alice")
				.with(httpBasic("alice", "test-alice-password"))).andExpect(status().isOk())
				.andExpect(jsonPath("$[0].status").value("OK"));
	}
}