package info.elexis.keycloak.authenticator;

import java.util.Optional;
import java.util.stream.Stream;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.access.DenyAccessAuthenticatorFactory;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.messages.Messages;

import jakarta.ws.rs.core.Response;

public class DenyAccessUserNoSecondFactorAuthenticator implements Authenticator {

	public static final String REQUIRE_OTP = "require-otp";
	public static final String REQUIRE_WEBAUTHN = "require-webauthn";
	public static final String REQUIREMENT_MODE = "requirement-mode";
	public static final String REQUIREMENT_MODE_REQUIRED = "REQUIRED";

	@Override
	public void authenticate(AuthenticationFlowContext context) {

		UserModel user = context.getUser();
		if (user == null) {
			context.failure(AuthenticationFlowError.UNKNOWN_USER);
			return;
		}

		AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
		boolean requireOtp = Boolean
				.parseBoolean(authenticatorConfig.getConfig().getOrDefault(REQUIRE_OTP, Boolean.FALSE.toString()));
		boolean requireWebauthn = Boolean
				.parseBoolean(authenticatorConfig.getConfig().getOrDefault(REQUIRE_WEBAUTHN, Boolean.FALSE.toString()));
		String requirementMode = authenticatorConfig.getConfig().getOrDefault(REQUIREMENT_MODE,
				REQUIREMENT_MODE_REQUIRED);

		boolean foundOtp = false;
		boolean foundWebauthn = false;
		if (requireOtp) {
			foundOtp = user.credentialManager().getStoredCredentialsStream()
					.anyMatch(credential -> OTPCredentialModel.TYPE.equals(credential.getType()));
		}
		if (requireWebauthn) {
			foundWebauthn = user.credentialManager().getStoredCredentialsStream()
					.anyMatch(credential -> WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(credential.getType())
							|| WebAuthnCredentialModel.TYPE_TWOFACTOR.equals(credential.getType()));
		}

		// req = 0, found = 1 = 1
		// req = 0, found = 0 = 1
		// req = 1, found = 0 = 0
		// req = 1, found = 1 = 1
		boolean otpReqSatisfied = requireOtp ? foundOtp : true;
		boolean webauthnReqSatisifed = requireWebauthn ? foundWebauthn : true;

		boolean overallSatisifed = REQUIREMENT_MODE_REQUIRED.equals(requirementMode)
				? otpReqSatisfied && webauthnReqSatisifed
				: otpReqSatisfied || webauthnReqSatisifed;

		if (overallSatisifed) {
			context.success();
		} else {
			String errorMessage = Optional.ofNullable(context.getAuthenticatorConfig())
					.map(AuthenticatorConfigModel::getConfig)
					.map(f -> f.get(DenyAccessAuthenticatorFactory.ERROR_MESSAGE)).orElse(Messages.ACCESS_DENIED);

			context.getEvent().error(Errors.ACCESS_DENIED);
			Response challenge = context.form().setError(errorMessage).createErrorPage(Response.Status.UNAUTHORIZED);
			context.failure(AuthenticationFlowError.ACCESS_DENIED, challenge);
		}

	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void action(AuthenticationFlowContext context) {
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

}
