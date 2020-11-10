package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Unroll
import org.opensaml.saml.saml2.core.Assertion

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat

class AuthenticationResponseSpec extends EEConnectorSpecification {

    static String REQUEST_TYPE_POST = "post"
    static String REQUEST_TYPE_GET = "get"

    Flow flow = new Flow(props)

    def setup() {
        flow.domesticSpService.signatureCredential = signatureCredential
        flow.domesticSpService.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTHENTICATION_RESPONSE_SUCCESS")
    def "get authentication response get"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_GET, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_RESPONSE_SUCCESS")
    def "get authentication response post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_POST, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_POST)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 200, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }


    @Unroll
    @Feature("AUTHENTICATION_RESULT_LIGHTTOKEN_ACCEPTANCE")
    def "request authentication with invalid lightToken"() {
        expect:
        String invalidToken = "specificCommunicationDefinitionConnectorResponse|b45e99b0-afef-44dc-b299-6ede26e5b61b|2020-11-02 10:12:15 522|WarR5kd669/NZiysHeRtog90PAZ3dAXeusmss8/Bl3s="
        String encodedToken = new String(Base64.getEncoder().encode(invalidToken.getBytes()))
        Response response = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.domesticConnector.fullEidasResponseUrl, encodedToken)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Token is invalid"))
    }

    @Unroll
    @Feature("AUTHENTICATION_RESULT_ENDPOINT")
    @Feature("AUTHENTICATION_RESULT_LIGHTTOKEN_ACCEPTANCE")
    def "request authentication response with other parameters"() {
        expect:
        String expiredEncodedToken = "c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlc3BvbnNlfGM4NGE4NGUyLWRhNmQtNGFkMi1hNGIwLWEwNWMzMDA2MTJiYnwyMDIwLTExLTA1IDAwOjIwOjM3IDcwOXxKdGtoVFlJYXZjMy9sU3ZjZm8yM2xSOGxabUpzQ2xELzlwQVZQYzJ2c1FnPQ=="
        Response response = Requests.getAuthorizationResponseFromEidasWithSomeUnusedParams(flow, method, flow.domesticConnector.fullEidasResponseUrl, expiredEncodedToken, paramName)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo(message))

        where:
        method            | paramName || statusCode || message
        REQUEST_TYPE_POST | "old"     || 400        || "Token is invalid or has expired"
        REQUEST_TYPE_GET  | "delay"   || 400        || "Token is invalid or has expired"
        REQUEST_TYPE_GET  | "token"   || 400        || "Duplicate request parameter 'token'"
    }

}
