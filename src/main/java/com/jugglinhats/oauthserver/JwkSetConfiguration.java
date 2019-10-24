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
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@Import(AuthorizationServerEndpointsConfiguration.class)
public class JwkSetConfiguration extends AuthorizationServerConfigurerAdapter {

	private final AuthenticationManager authenticationManager;

	public JwkSetConfiguration(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		// @formatter:off
		endpoints
			.authenticationManager(this.authenticationManager)
			.requestFactory(requestFactory(null))
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
					.scopes("read", "write")
					.and()
				.withClient("client-b")
					.authorizedGrantTypes("password")
					.secret("{noop}client-b-password")
					.scopes("read");
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

	@Bean
	public OAuth2RequestFactory requestFactory(@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") ClientDetailsService clientDetailsService) {
		DefaultOAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
		requestFactory.setCheckUserScopes(true);
		return requestFactory;
	}

	@Bean
	public TokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter() {
		return new TokenEndpointAuthenticationFilter(this.authenticationManager, requestFactory(null));
	}

}
