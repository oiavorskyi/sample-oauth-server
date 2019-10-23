package com.jugglinhats.oauthserver;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration;

@Configuration
class JwkSetEndpointConfiguration extends AuthorizationServerSecurityConfiguration {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		//@formatter:off
		http
			.requestMatchers()
				.mvcMatchers("/.well-known/jwks.json")
				.and()
			.authorizeRequests()
				.mvcMatchers("/.well-known/jwks.json").permitAll();
		//@formatter:on
	}
}
