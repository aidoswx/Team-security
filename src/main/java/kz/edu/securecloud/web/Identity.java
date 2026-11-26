package kz.edu.securecloud.web;
import org.springframework.security.core.context.SecurityContextHolder;
public final class Identity {
	private Identity() {
	}
	public static void require(String claimed) {
		var auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !auth.isAuthenticated() || !auth.getName().equals(claimed))
			throw new SecurityException("Identity does not match authenticated user");
	}
}