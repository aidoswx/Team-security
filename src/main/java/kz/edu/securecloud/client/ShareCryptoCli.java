package kz.edu.securecloud.client;
import java.io.Console;
import java.nio.file.*;
import java.util.Arrays;
import kz.edu.securecloud.crypto.*;
/** Local key exchange: the private key stays in a password-encrypted vault. */
public final class ShareCryptoCli {
	private ShareCryptoCli() {
	}
	public static void main(String[] args) throws Exception {
		if (args.length == 2 && args[0].equals("fingerprint")) {
			var keys = new KeyManagementService();
			System.out.println(keys.fingerprint(keys.readPublicKey(Files.readAllBytes(Path.of(args[1])))));
			return;
		}
		boolean generate = args.length == 3 && args[0].equals("keygen");
		boolean wrap = args.length == 7 && args[0].equals("wrap");
		boolean open = args.length == 8 && args[0].equals("open");
		if (!generate && !wrap && !open) {
			System.err.println(
					"keygen <public.der> <private.scv>\nfingerprint <public.der>\nwrap <file.scv> <public.der> <key.wrapped> <owner> <fileName> <version>\nopen <file.scv> <private.scv> <key.wrapped> <output> <owner> <fileName> <version>");
			System.exit(2);
		}
		Console console = System.console();
		if (console == null)
			throw new IllegalStateException("Run in an interactive terminal");
		char[] password = console.readPassword(wrap ? "File encryption password: " : "Private key vault password: ");
		if (password == null)
			throw new IllegalStateException("Password input cancelled");
		var keys = new KeyManagementService();
		var crypto = new EncryptionService();
		try {
			if (generate) {
				if (Files.exists(Path.of(args[1])) || Files.exists(Path.of(args[2])))
					throw new IllegalArgumentException("Output already exists");
				var pair = keys.generate();
				write(args[2], keys.protectPrivateKey(pair.getPrivate(), password));
				write(args[1], pair.getPublic().getEncoded());
				console.printf("Public key SHA-256: %s%n", keys.fingerprint(pair.getPublic()));
			} else if (wrap) {
				byte[] aad = crypto.associatedData(args[4], args[5], Integer.parseInt(args[6]));
				write(args[3], keys.wrapFileKey(Files.readAllBytes(Path.of(args[1])), password,
						keys.readPublicKey(Files.readAllBytes(Path.of(args[2]))), aad));
			} else {
				var privateKey = keys.unlockPrivateKey(Files.readAllBytes(Path.of(args[2])), password);
				byte[] aad = crypto.associatedData(args[5], args[6], Integer.parseInt(args[7]));
				byte[] plaintext = keys.openSharedFile(Files.readAllBytes(Path.of(args[1])),
						Files.readAllBytes(Path.of(args[3])), privateKey, aad);
				try {
					write(args[4], plaintext);
				} finally {
					Arrays.fill(plaintext, (byte) 0);
				}
			}
		} finally {
			Arrays.fill(password, '\0');
		}
	}
	private static void write(String path, byte[] bytes) throws java.io.IOException {
		Files.write(Path.of(path), bytes, StandardOpenOption.CREATE_NEW);
	}
}