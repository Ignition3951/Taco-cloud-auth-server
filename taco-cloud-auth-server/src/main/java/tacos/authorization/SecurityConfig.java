package tacos.authorization;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

		httpSecurity.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated());

		return httpSecurity.formLogin().and().build();
	}

	@Bean
	UserDetailsService userDetailsService(PasswordEncoder encoder) {
		List<UserDetails> list = new ArrayList<>();
		list.add(new User("habuma", encoder.encode("password"),
				Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
		list.add(
				new User("tacochef", encoder.encode("password"),
						Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
		return new InMemoryUserDetailsManager(list);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// Comment 1asdasd

}
