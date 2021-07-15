/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.flowable.ui.idm.service.keycloak;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.flowable.common.engine.api.FlowableException;
import org.flowable.common.engine.impl.interceptor.CommandContext;
import org.flowable.idm.api.User;
import org.flowable.idm.engine.impl.UserQueryImpl;
import org.flowable.idm.engine.impl.persistence.entity.UserEntityImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * @author Filip Hrisafov
 */
public class KeycloakUserTenantQueryImpl extends UserQueryImpl {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	protected static final ParameterizedTypeReference<List<KeycloakUserRepresentation>> KEYCLOAK_LIST_OF_USERS = new ParameterizedTypeReference<List<KeycloakUserRepresentation>>() {

	};

	protected static final Logger LOGGER = LoggerFactory.getLogger(KeycloakUserQueryImpl.class);

	protected KeycloakConfiguration keycloakConfiguration;

	public KeycloakUserTenantQueryImpl(KeycloakConfiguration keycloakConfiguration) {
		this.keycloakConfiguration = keycloakConfiguration;
	}

	@Override
	public long executeCount(CommandContext commandContext) {
		// GET /{realm}/users/count
		// Query parameters: username, email, firstName, lastName, search(email, first,
		// last or username)
		// paging first, max

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

		String tenantId = oidcUser.getAttribute("tenantId");
		if (tenantId == null) {
			String userName = oidcUser.getPreferredUsername();

			throw new FlowableException(
					new StringBuilder("TenantId is Null or Invalid for user ").append(userName).toString());
		}
		StringBuilder userBytenantidUrlBuilder = new StringBuilder(keycloakConfiguration.getServer())
				.append("auth/realms/").append(keycloakConfiguration.getRealm())
				.append("/ext-user-rest-api/users/search/attribute/count/tenantId/").append(tenantId);

		URI uri = URI.create(userBytenantidUrlBuilder.toString());

		// UriComponentsBuilder builder = prepareQuery("/users/count");
		// URI uri = builder.buildAndExpand(keycloakConfiguration.getRealm()).toUri();
		// uri = URI.create(
		// "http://localhost:9090/auth/realms/Adapt/ext-user-rest-api/users/search/attribute/count/tenantId/aneers");

		ResponseEntity<Long> response = keycloakConfiguration.getRestTemplate().getForEntity(uri, Long.class);
		HttpStatus statusCode = response.getStatusCode();
		if (statusCode.is2xxSuccessful()) {
			LOGGER.debug("Successful response from keycloak");
			Long usersCount = response.getBody();
			if (usersCount != null) {
				return usersCount;
			} else {
				LOGGER.warn("Keycloak didn't return any body when querying users");
				return 0;
			}
		} else {
			throw new FlowableException("Keycloak returned status code: " + statusCode);
		}
	}

	@Override
	public List<User> executeList(CommandContext commandContext) {

		// GET /{realm}/users
		// Query parameters: username, email, firstName, lastName, search(email, first,
		// last or username)
		// paging first, max

		UriComponentsBuilder builder = prepareQuery("/users");

		if (getMaxResults() >= 0) {
			builder.queryParam("max", getMaxResults());
		}

		if (getFirstResult() >= 0) {
			builder.queryParam("first", getFirstResult());
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

		String tenantId = oidcUser.getAttribute("tenantId");
		String userName = oidcUser.getPreferredUsername();
		if (tenantId == null) {

			throw new FlowableException(
					new StringBuilder("TenantId is Null or Invalid for user ").append(userName).toString());
		}
		StringBuilder userBytenantidUrlBuilder = new StringBuilder(keycloakConfiguration.getServer())
				.append("auth/realms/").append(keycloakConfiguration.getRealm())
				.append("/ext-user-rest-api/users/search/attribute/tenantId/").append(tenantId);

		URI uri = URI.create(userBytenantidUrlBuilder.toString());

//		URI uri = builder.buildAndExpand(keycloakConfiguration.getRealm()).toUri();
//		uri = URI.create(
//				"http://localhost:9090/auth/realms/Adapt/ext-user-rest-api/users/search/attribute/tenantId/aneers");

		ResponseEntity<List<KeycloakUserRepresentation>> response = keycloakConfiguration.getRestTemplate()
				.exchange(uri, HttpMethod.GET, null, KEYCLOAK_LIST_OF_USERS);

		HttpStatus statusCode = response.getStatusCode();
		if (statusCode.is2xxSuccessful()) {
			LOGGER.debug("Successful response from keycloak");
			List<KeycloakUserRepresentation> keycloakUsers = response.getBody();
			if (keycloakUsers != null) {
				List<User> users = new ArrayList<>(keycloakUsers.size());
				for (KeycloakUserRepresentation keycloakUser : keycloakUsers) {

					try {
						if (!keycloakUser.getEnabled()) {
							throw new FlowableException(
									new StringBuilder("User ").append(userName).append(" is disabled!!!").toString());
						}

						if (keycloakUser.getTenantId() == null) {
							throw new FlowableException(new StringBuilder("TenantId for user ").append(userName)
									.append(" cannot be null!!!").toString());
						}

						User user = new UserEntityImpl();
						user.setId(keycloakUser.getId());
						user.setFirstName(keycloakUser.getFirstName());
						user.setLastName(keycloakUser.getLastName());
						user.setEmail(keycloakUser.getEmail());

						user.setTenantId(keycloakUser.getTenantId());
						users.add(user);

					} catch (FlowableException e) {
						LOGGER.error(e.getMessage());
					}

				}
				return users;
			} else {
				LOGGER.warn("Keycloak didn't return any body when querying users");
				return Collections.emptyList();
			}
		} else {
			throw new FlowableException("Keycloak returned status code: " + statusCode);
		}
	}

	protected UriComponentsBuilder prepareQuery(String path) {
		UriComponentsBuilder builder = UriComponentsBuilder
				.fromHttpUrl(keycloakConfiguration.getServer() + "auth/admin/realms/{realm}" + path);

		if (getId() != null) {
			builder.queryParam("username", getId());
		} else if (getIdIgnoreCase() != null) {
			builder.queryParam("username", getIdIgnoreCase());
		} else if (getFullNameLike() != null) {
			builder.queryParam("search", getFullNameLike());
		} else if (getFullNameLikeIgnoreCase() != null) {
			builder.queryParam("search", getFullNameLikeIgnoreCase());
		}

		return builder;
	}

}
