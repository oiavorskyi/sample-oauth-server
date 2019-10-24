package com.jugglinhats.oauthserver;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	@Override
	protected UserDetailsService userDetailsService() {
		//@formatter:off
		return new InMemoryUserDetailsManager(
				User.withUsername("user")
					.passwordEncoder(passwordEncoder()::encode)
					.password("password")
					.authorities("read", "write")
					.build(),
				User.withUsername("readonly")
					.passwordEncoder(passwordEncoder()::encode)
					.password("readonly-password")
					.authorities("read")
					.build()
		);
		//@formatter:on
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}
