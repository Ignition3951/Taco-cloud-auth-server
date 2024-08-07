package tacos.authorization;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

//	@Autowired
//	private CustomAuthenticationProvider customAuthenticationProvider;

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

		httpSecurity.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().permitAll());

		return httpSecurity.formLogin(Customizer.withDefaults()).build();
	}

//	@Autowired
//	public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder) {
//		authenticationManagerBuilder.authenticationProvider(customAuthenticationProvider);
//	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		String password = bCryptPasswordEncoder.encode("12345");
		UserDetails userDetails = User.withUsername("utk").password(password).roles("USER").build();
		return new InMemoryUserDetailsManager(userDetails);
	}

	// Comment 1asdasd

}
