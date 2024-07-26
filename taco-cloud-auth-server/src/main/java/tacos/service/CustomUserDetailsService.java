package tacos.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import tacos.model.User;
import tacos.repo.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

//	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
//	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username);
		if(user==null) {
			throw new UsernameNotFoundException("User not found!!!!!!!!");
		}
		return new org.springframework.security.core.userdetails.User(
				user.getUsername(),
				user.getPassword(),
				user.isEnabled(),
				user.isAccountNonExpired(),
				user.isCredentialsNonExpired(),
				user.isAccountNonLocked(),
				getAuthorities(Arrays.asList("ROLE_USER", "ROLE_ADMIN")));
	}

	private Collection<? extends GrantedAuthority> getAuthorities(List<String> userRoles) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		for (String role : userRoles) {
			authorities.add(new SimpleGrantedAuthority(role));
		}
		return authorities;
	}

}
