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
package org.flowable.ui.common.security;

import org.flowable.common.engine.api.FlowableException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * @author Filip Hrisafov
 */
public class FlowableAdaptAuthenticationSecurityScope extends FlowableAuthenticationSecurityScope {

	public FlowableAdaptAuthenticationSecurityScope(Authentication authentication) {
		super(authentication);
	}

	@Override
	public String getTenantId() {
		OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
		String username = oidcUser.getPreferredUsername();
		if (username == null) {
			throw new FlowableException(" Username cannot be null!!!");
		}

		String tenantId = username.split("-")[0];

		if (tenantId.equals(username)) {
			throw new FlowableException(
					new StringBuilder("TenantId is Null or Invalid for user ").append(username).toString());
		}

		return tenantId;

	}

}
