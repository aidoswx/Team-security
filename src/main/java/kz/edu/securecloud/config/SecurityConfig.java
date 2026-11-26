package kz.edu.securecloud.config;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
public class SecurityConfig {
	@Bean
	UserDetailsService users(@Value("${app.alice-password}") String alice, @Value("${app.bob-password}") String bob) {
		if (alice.length() < 12 || bob.length() < 12)
			throw new IllegalArgumentException("Account passwords need at least 12 characters");
		var encoder = new BCryptPasswordEncoder();
		return new InMemoryUserDetailsManager(
				User.withUsername("alice").password(encoder.encode(alice)).roles("USER").build(),
				User.withUsername("bob").password(encoder.encode(bob)).roles("USER").build());
	}
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Bean
	SecurityFilterChain api(HttpSecurity http) throws Exception {
		return http.csrf(csrf -> csrf.disable())
				.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(a -> a.anyRequest().authenticated()).httpBasic(Customizer.withDefaults())
				.build();
	}
}