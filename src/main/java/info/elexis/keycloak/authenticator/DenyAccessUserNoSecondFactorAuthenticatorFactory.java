package info.elexis.keycloak.authenticator;

import java.util.Arrays;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DenyAccessUserNoSecondFactorAuthenticatorFactory implements AuthenticatorFactory {

	private static final DenyAccessUserNoSecondFactorAuthenticator SINGLETON = new DenyAccessUserNoSecondFactorAuthenticator();
	public static final String ERROR_MESSAGE = "denyErrorMessage";

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return "deny-access-user-no-secondfactor";
	}

	@Override
	public String getDisplayType() {
		return "Deny access without second authentication factor";
	}

	@Override
	public String getReferenceCategory() {
		return null;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED };

	@Override
	public Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return "Deny access if the current user hasn't set up a second factor, as specified in the configuration.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {

		final ProviderConfigProperty requireOtpConfigProperty = new ProviderConfigProperty();
		requireOtpConfigProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		requireOtpConfigProperty.setName(DenyAccessUserNoSecondFactorAuthenticator.REQUIRE_OTP);
		requireOtpConfigProperty.setLabel("Require OTP");
		requireOtpConfigProperty.setDefaultValue(Boolean.FALSE);
		requireOtpConfigProperty.setHelpText("Require configured One-Time-Pass credential");

		final ProviderConfigProperty requireWebauthnConfigProperty = new ProviderConfigProperty();
		requireWebauthnConfigProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		requireWebauthnConfigProperty.setName(DenyAccessUserNoSecondFactorAuthenticator.REQUIRE_WEBAUTHN);
		requireWebauthnConfigProperty.setLabel("Require WebAuthn");
		requireWebauthnConfigProperty.setDefaultValue(Boolean.FALSE);
		requireWebauthnConfigProperty.setHelpText("Require configured WebAuthn credential");

		final ProviderConfigProperty requireMode = new ProviderConfigProperty();
		requireMode.setType(ProviderConfigProperty.LIST_TYPE);
		requireMode.setName(DenyAccessUserNoSecondFactorAuthenticator.REQUIREMENT_MODE);
		requireMode.setOptions(Arrays.asList("REQUIRED", "ALTERNATIVE"));
		requireMode.setDefaultValue(DenyAccessUserNoSecondFactorAuthenticator.REQUIREMENT_MODE_REQUIRED);
		requireMode.setLabel("Requirement mode");
		requireMode
				.setHelpText("REQUIRE both Otp and WebAuthn to be configured, or at least one of them as ALTERNATIVE");

		final ProviderConfigProperty errorMessage = new ProviderConfigProperty();
		errorMessage.setType(ProviderConfigProperty.STRING_TYPE);
		errorMessage.setName(ERROR_MESSAGE);
		errorMessage.setLabel("Error message");
		errorMessage.setHelpText("Error message which will be shown to the user. "
				+ "You can directly define particular message or property, which will be used for mapping the error message f.e `deny-access-role1`. "
				+ "If the field is blank, default property 'access-denied' is used.");

		return Arrays.asList(requireOtpConfigProperty, requireWebauthnConfigProperty, requireMode, errorMessage);

	}

}
