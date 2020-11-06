package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import org.opensaml.saml.saml2.core.Assertion
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import org.apache.commons.lang.RandomStringUtils


class AuthenticationSpec extends EEConnectorSpecification {

    static String REQUEST_TYPE_POST = "post"
    static String REQUEST_TYPE_GET = "get"

    Flow flow = new Flow(props)

    def setup() {
        flow.domesticSpService.signatureCredential = signatureCredential
        flow.domesticSpService.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")

        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_POST, samlRequest)
        assertThat(response.getStatusCode(), Matchers.equalTo(200))
        String lightTokenForRequest = response.getBody().htmlPath().getString("**.find { it.@name == 'token' }.@value")
        String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")

        Response response1 = Requests.sendLightTokenRequestToEidas(flow, lightTokenRequestUrl, lightTokenForRequest)
        String samlRequest2 = response1.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value")
        String actionUrl = response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")

        Response response2 = Requests.colleagueRequest(flow, REQUEST_TYPE_POST, samlRequest2, actionUrl)
        String action = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response3 = Requests.proxyServiceRequest(flow, REQUEST_TYPE_POST, action, token)
        response3.getStatusCode()
        String action2 = response3.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspRequest = response3.body().htmlPath().get("**.find {it.@id == 'SMSSPRequest'}.@value")

        Response response4 = Requests.idpRequest(flow, REQUEST_TYPE_POST, action2, smsspRequest)
        String smsspToken = response4.body().htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response4.body().htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")

        Response response5 = Requests.idpAuthorizationRequest(flow, smsspToken, smsspTokenRequestJson)
        String action3 = response5.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response5.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")

        Response response6 = Requests.idpAuthorizationResponse(flow, action3, smsspTokenResponse)
        String binaryLightToken = response6.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")

        Response response7 = Requests.afterCitizenConsentResponse(flow, binaryLightToken)
        String action5 = response7.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token2 = response7.body().htmlPath().get("**.find {it.@id == 'token'}.@value")

        Response response8 = Requests.proxyServiceRequest(flow, REQUEST_TYPE_POST, action5, token2)
        String samlResponse = response8.body().htmlPath().get("**.find {it.@id == 'ColleagueResponse_SAMLResponse'}.@value")

        Response response9 = Requests.colleagueResponse(flow, samlResponse)
        String token3 = response9.body().htmlPath().get("**.find {it.@id == 'token'}.@value")
        String actionUrl6 = response9.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")

        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, actionUrl6, token3)
        assertEquals("Correct HTTP status code is returned", response10.statusCode(), 200)
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION")
    def "request authentication with get"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        String relayState = "ABC-" + RandomStringUtils.random(76, true, true)

        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest, "RelayState", relayState)
        String actionUrl = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String samlRequest2 = response.body().htmlPath().get("**.find {it.@name == 'redirectForm'}input[0].@value")

        Response response2 = Requests.colleagueRequest(flow, REQUEST_TYPE_GET, samlRequest2, actionUrl)
        String action = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response3 = Requests.proxyServiceRequest(flow, REQUEST_TYPE_GET, action, token)
        response3.getStatusCode()
        String action2 = response3.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspRequest = response3.body().htmlPath().get("**.find {it.@id == 'SMSSPRequest'}.@value")

        Response response4 = Requests.idpRequest(flow, REQUEST_TYPE_GET, action2, smsspRequest)
        String smsspToken = response4.body().htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response4.body().htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")

        Response response5 = Requests.idpAuthorizationRequest(flow, smsspToken, smsspTokenRequestJson)
        String action3 = response5.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response5.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")

        Response response6 = Requests.idpAuthorizationResponse(flow, action3, smsspTokenResponse)
        String binaryLightToken = response6.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")

        Response response7 = Requests.afterCitizenConsentResponse(flow, binaryLightToken)
        String action5 = response7.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token2 = response7.body().htmlPath().get("**.find {it.@id == 'token'}.@value")

        Response response8 = Requests.proxyServiceRequest(flow, REQUEST_TYPE_GET, action5, token2)
        String samlResponse = response8.body().htmlPath().get("**.find {it.@id == 'ColleagueResponse_SAMLResponse'}.@value")

        Response response9 = Requests.colleagueResponse(flow, samlResponse)
        String token3 = response9.body().htmlPath().get("**.find {it.@id == 'token'}.@value")
        String actionUrl6 = response9.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")

        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, actionUrl6, token3)
        assertEquals("Correct HTTP status code is returned", response10.statusCode(), 302)
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    def "request authentication with multiple instances"() {
        expect:
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_POST, "1234567", "SAMLRequest", "78901234")
        assertEquals("Correct HTTP status code is returned", response.statusCode(), 400)
        assertEquals("Correct content type", response.getContentType(), "application/json")
        assertThat(response.body().jsonPath().get("message"), Matchers.equalTo("Duplicate request parameter 'SAMLRequest'"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SP_CHECK")
    def "request authentication with invalid service provider"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithInvalidIssuer(flow, "eidas-eeserviceprovider")
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", response.statusCode(), 400)
        assertEquals("Correct content type", response.getContentType(), "application/json")
        assertThat(response.body().jsonPath().get("message"), Matchers.equalTo("SAML request is invalid - issuer not allowed"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with missing attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithoutExtensions(flow, "eidas-eeserviceprovider")
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", response.statusCode(), 400)
        assertEquals("Correct content type", response.getContentType(), "application/json")
        assertThat(response.body().jsonPath().get("message"), Matchers.equalTo("SAML request is invalid - no requested attributes"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with unsupported attribute"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithUnsupportedAttribute(flow, "eidas-eeserviceprovider")
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", response.statusCode(), 400)
        assertEquals("Correct content type", response.getContentType(), "application/json")
        assertThat(response.body().jsonPath().get("message"), Matchers.equalTo("SAML request is invalid - unsupported requested attributes"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

}
