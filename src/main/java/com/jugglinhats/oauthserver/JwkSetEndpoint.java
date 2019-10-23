package com.jugglinhats.oauthserver;

import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@FrameworkEndpoint
class JwkSetEndpoint {

	@GetMapping("/.well-known/jwks.json")
	@ResponseBody
	public Map<String, Object> getKey(Principal principal) {
		RSAPublicKey publicKey = (RSAPublicKey) jwtKey().getPublic();
		RSAKey key = new RSAKey.Builder(publicKey).build();
		return new JWKSet(key).toJSONObject();
	}

	@Bean
	public KeyPair jwtKey() {
		KeyStoreKeyFactory keyStoreKeyFactory =
				new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "password".toCharArray());
		return keyStoreKeyFactory.getKeyPair("jwt");
	}
}
