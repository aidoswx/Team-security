package kz.edu.securecloud.client;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import kz.edu.securecloud.crypto.EncryptedFileCodec;
import kz.edu.securecloud.crypto.EncryptedPayload;
import kz.edu.securecloud.crypto.EncryptionService;

/**
 * Minimal local client: plaintext and passwords never leave the user's
 * computer.
 */
public final class LocalCryptoCli {

	private LocalCryptoCli() {
	}

	public static void main(String[] args) throws IOException {
		if (args.length != 6 || !("encrypt".equals(args[0]) || "decrypt".equals(args[0]))) {
			printUsage();
			System.exit(2);
		}

		Console console = System.console();
		if (console == null) {
			throw new IllegalStateException("Run this command in a terminal so the password can be hidden");
		}

		Path input = Path.of(args[1]).toAbsolutePath().normalize();
		Path output = Path.of(args[2]).toAbsolutePath().normalize();
		String ownerId = args[3];
		String logicalFileName = args[4];
		int version = Integer.parseInt(args[5]);
		byte[] associatedData = new EncryptionService().associatedData(ownerId, logicalFileName, version);
		char[] password = console.readPassword("Password: ");

		try {
			if ("encrypt".equals(args[0])) {
				encrypt(input, output, password, associatedData);
			} else {
				decrypt(input, output, password, associatedData);
			}
			console.printf("Done: %s%n", output);
		} finally {
			Arrays.fill(password, '\0');
			Arrays.fill(associatedData, (byte) 0);
		}
	}

	private static void encrypt(Path input, Path output, char[] password, byte[] associatedData) throws IOException {
		byte[] plaintext = Files.readAllBytes(input);
		try {
			EncryptedPayload payload = new EncryptionService().encrypt(plaintext, password, associatedData);
			Files.write(output, EncryptedFileCodec.encode(payload));
		} finally {
			Arrays.fill(plaintext, (byte) 0);
		}
	}

	private static void decrypt(Path input, Path output, char[] password, byte[] associatedData) throws IOException {
		EncryptedPayload payload = EncryptedFileCodec.decode(Files.readAllBytes(input));
		byte[] plaintext = new EncryptionService().decrypt(payload, password, associatedData);
		try {
			Files.write(output, plaintext);
		} finally {
			Arrays.fill(plaintext, (byte) 0);
		}
	}

	private static void printUsage() {
		System.err.println(
				"Usage: LocalCryptoCli <encrypt|decrypt> <input> <output> <ownerId> <originalFileName> <version>");
	}
}
