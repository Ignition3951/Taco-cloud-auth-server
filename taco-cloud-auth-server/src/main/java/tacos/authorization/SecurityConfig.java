package tacos.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import tacos.service.CustomAuthenticationProvider;

@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private CustomAuthenticationProvider customAuthenticationProvider;

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

		httpSecurity.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated());

		return httpSecurity.formLogin(Customizer.withDefaults()).build();
	}

	@Autowired
	public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder) {
		authenticationManagerBuilder.authenticationProvider(customAuthenticationProvider);
	}

//	@Bean
//	UserDetailsService userDetailsService(PasswordEncoder encoder) {
//		List<UserDetails> list = new ArrayList<>();
//		list.add(new User("habuma", encoder.encode("password"),
//				Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
//		list.add(
//				new User("tacochef", encoder.encode("password"),
//						Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
//		return new InMemoryUserDetailsManager(list);
//	}

//	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
//	}

	// Comment 1asdasd

}
