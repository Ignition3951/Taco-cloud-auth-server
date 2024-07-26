package tacos;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import tacos.model.User;
import tacos.repo.UserRepository;

@SpringBootApplication
public class TacoCloudAuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(TacoCloudAuthServerApplication.class, args);
	}

	@Bean
	public ApplicationRunner dataLoader(UserRepository repo, PasswordEncoder encoder) {
		return args -> {
			repo.save(new User("habuma", encoder.encode("password"), "ROLE_USER", null, null, null, null, null));
			repo.save(new User("tacochef", encoder.encode("password"), "ROLE_USER", null, null, null, null, null));
		};
	}
}
