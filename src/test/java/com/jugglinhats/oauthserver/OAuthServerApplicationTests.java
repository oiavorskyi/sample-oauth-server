package com.jugglinhats.oauthserver;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class OAuthServerApplicationTests {

	@Autowired
	private MockMvc client;

	@Test
	public void exposesJwksEndpoint() throws Exception {
		client.perform(get("/.well-known/jwks.json").accept(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.keys").isNotEmpty());
	}

	@Test
	public void supportsPasswordGrantForPredefinedClient() throws Exception {
		//@formatter:off
		client.perform(post("/oauth/token")
					.with(clientACredentials())
					.with(passwordOAuthGrantRequest(ofStandardUser())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty());
		//@formatter:on
	}

	@Test
	public void rejectsRequestIfThereWereNoClientCredentialsProvided() throws Exception {
		//@formatter:off
		client.perform(post("/oauth/token"))
				.andExpect(status().isUnauthorized());
		//@formatter:on
	}

	@Test
	public void rejectsRequestIfClientCredentialsAreWrong() throws Exception {
		//@formatter:off
		client.perform(post("/oauth/token")
				.with(httpBasic("wrong-client", "any-password")))
				.andExpect(status().isUnauthorized());

		client.perform(post("/oauth/token")
				.with(httpBasic("client-a", "wrong-password")))
				.andExpect(status().isUnauthorized());
		//@formatter:on
	}

	@Test
	public void deniesTokenIfWrongUserCredentials() throws Exception {
		//@formatter:off
		client.perform(post("/oauth/token")
				.with(clientACredentials())
				.with(passwordOAuthGrantRequest(ofAUser("wrongUser", "anyPassword"))))
				.andExpect(status().is4xxClientError())
				.andExpect(jsonPath("$.error").value("unauthorized"));
		//@formatter:on
	}

	@Test
	public void deniesTokenIfRequestedScopeIsNotAllowedForClient() throws Exception {
		//@formatter:off
		client.perform(post("/oauth/token")
				.with(clientACredentials())
				.with(passwordOAuthGrantRequest(ofStandardUser()))
				.param("scope", "ruletheworld"))
				.andExpect(status().is4xxClientError())
				.andExpect(jsonPath("$.error").value("invalid_scope"));
		//@formatter:on
	}

	@Test
	public void grantsTokenWithScopesAllowedToBothClientEndUser() throws Exception {
		//@formatter:off
		client.perform(post("/oauth/token")
					.with(clientACredentials())
					.with(passwordOAuthGrantRequest(ofStandardUser())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.scope").value("read write"));

		client.perform(post("/oauth/token")
					.with(clientACredentials())
					.with(passwordOAuthGrantRequest(ofReadonlyUser())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.scope").value("read"));

		client.perform(post("/oauth/token")
					.with(clientBCredentials())
					.with(passwordOAuthGrantRequest(ofStandardUser())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.scope").value("read"));
		//@formatter:on
	}

	private RequestPostProcessor ofStandardUser() {
		return ofAUser("user", "password");
	}

	private RequestPostProcessor ofReadonlyUser() {
		return ofAUser("readonly", "readonly-password");
	}

	private RequestPostProcessor ofAUser(String username, String password) {
		return request -> {
			request.addParameter("username", username);
			request.addParameter("password", password);

			return request;
		};
	}

	private RequestPostProcessor clientACredentials() {
		return httpBasic("client-a", "client-a-password");
	}

	private RequestPostProcessor clientBCredentials() {
		return httpBasic("client-b", "client-b-password");
	}

	private RequestPostProcessor passwordOAuthGrantRequest(RequestPostProcessor credentialsPostProcessor) {
		return request -> {
			request.addParameter("grant_type", "password");
			request.setContentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE);

			return credentialsPostProcessor.postProcessRequest(request);
		};
	}
}
