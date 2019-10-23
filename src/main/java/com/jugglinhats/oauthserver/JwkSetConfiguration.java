package com.jugglinhats.oauthserver;

import java.security.KeyPair;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@Import(AuthorizationServerEndpointsConfiguration.class)
public class JwkSetConfiguration extends AuthorizationServerConfigurerAdapter {

	private AuthenticationManager authenticationManager;

	public JwkSetConfiguration(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		// @formatter:off
		endpoints
			.authenticationManager(this.authenticationManager)
			.accessTokenConverter(accessTokenConverter(null))
			.tokenStore(tokenStore());
		// @formatter:on
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		// @formatter:off
		clients.inMemory()
				.withClient("client-a")
					.authorizedGrantTypes("password")
					.secret("{noop}client-a-password")
					.scopes("read", "write");
		// @formatter:on

	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter(null));
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter(KeyPair jwtKey) {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setKeyPair(jwtKey);
		return converter;
	}

}
