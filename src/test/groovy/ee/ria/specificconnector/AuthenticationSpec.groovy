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
import java.nio.charset.StandardCharsets
import static org.junit.Assert.assertTrue


class AuthenticationSpec extends EEConnectorSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.domesticSpService.signatureCredential = signatureCredential
        flow.domesticSpService.encryptionCredential = encryptionCredential
        flow.domesticSpService.metadataCredential = metadataCredential
        flow.domesticSpService.expiredCredential = expiredCredential
        flow.domesticSpService.unsupportedCredential = unsupportedCredential
        flow.domesticSpService.unsupportedByConfigurationCredential = unsupportedByConfigurationCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertThat(response.getStatusCode(), Matchers.equalTo(200))
        String lightTokenForRequest = response.getBody().htmlPath().getString("**.find { it.@name == 'token' }.@value")
        String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")

        Response response1 = Requests.sendLightTokenRequestToEidas(flow, lightTokenRequestUrl, lightTokenForRequest)
        flow.setRequestMessage(response1.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value"))
        flow.setNextEndpoint(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action"))

        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_POST)

        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 200, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with get"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        String relayState = "ABC-" + RandomStringUtils.random(76, true, true)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest, "RelayState", relayState)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        Response response1 = Steps.followRedirect(flow, response)
        flow.setNextEndpoint(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action"))
        flow.setRequestMessage(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}input[0].@value"))

        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)
        
        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    def "request authentication with multiple instances"() {
        expect:
        Response response = Requests.startAuthenticationWithDuplicateParams(flow, REQUEST_TYPE_POST, "1234567", additionalParam, "78901234")
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo(message))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())

        where:
        additionalParam || statusCode || message
        "SAMLRequest"   || 400        || "Duplicate request parameter 'SAMLRequest'"
        "country"       || 400        || "Duplicate request parameter 'country'"
        "RelayState"    || 400        || "Duplicate request parameter 'RelayState'"
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    def "request authentication with invalid parameters. Expected error message: [#message]"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        def map = [:]
        // Spock specific workaround
        def map1 = SamlUtils.setUrlParameter(map, param1, samlRequest)
        def map2 = SamlUtils.setUrlParameter(map, param2, param2Value)
        def map3 = SamlUtils.setUrlParameter(map, param3, param3Value)

        Response response = Requests.startAuthenticationWithParameters(flow, REQUEST_TYPE_POST, map)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message"), Matchers.startsWith(message))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())

        where:
        param1        | param2        | param2Value | param3       | param3Value                                                                         || statusCode || message
        _             | _             | _           | _            | _                                                                                   || 400        || "Required String parameter 'SAMLRequest' is not present"
        "SAMLRequest" | _             | _           | _            | _                                                                                   || 400        || "Required String parameter 'country' is not present"
        "SAMLRequest" | "country"     | _           | _            | _                                                                                   || 400        || "post.country: must match "
        "SAMLRequest" | "country"     | "CAA"       | _            | _                                                                                   || 400        || "post.country: must match "
        "SAMLRequest" | "country"     | "CA"        | "RelayState" | "1XyyAocKwZp8Zp8qd9lhVKiJPF1AywyfpXTLqYGLFE73CKcEgSKOrfVq9UMfX9HAfWwBJMI9O7Bm22BZ1" || 400        || "post.RelayState: must match"
        "SAMLRequest" | "country"     | "CA"        | "RelayState" | "\b\f"                                                                              || 400        || "post.RelayState: must match"
        _             | "SAMLRequest" | "Ää"        | "country"    | "CA"                                                                                || 400        || "post.SAMLRequest: must match"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SP_CHECK")
    def "request authentication with invalid service provider"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithInvalidIssuer(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("SAML request is invalid - issuer not allowed"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with missing attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithoutExtensions(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("SAML request is invalid - no requested attributes"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with unsupported attribute"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithUnsupportedAttribute(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("SAML request is invalid - unsupported requested attributes"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with invalid signing certificate #credential.entityId"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithInvalidCredential(flow, credential)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("SAML request is invalid - invalid signature"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())

        where:
        credential                           || statusCode
        metadataCredential                   || 400
        expiredCredential                    || 400
        unsupportedCredential                || 400
        unsupportedByConfigurationCredential || 400
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    def "request authentication GET with invalid saml request. #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, attributeName, attributeValue)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message"), Matchers.startsWith(message))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())

        where:
        attributeName  | attributeValue                                          || message
        "IsPassive"    | true                                                    || "SAML request is invalid - expecting IsPassive to be false"
        "ForceAuthn"   | _                                                       || "SAML request is invalid - expecting ForceAuthn to be true"
        "ForceAuthn"   | false                                                   || "SAML request is invalid - expecting ForceAuthn to be true"
        "ID"           | _                                                       || "SAML request is invalid - does not conform to schema"
        "ID"           | "31"                                                    || "SAML request is invalid - does not conform to schema"
        "IssueInstant" | _                                                       || "SAML request is invalid - does not conform to schema"
        "Version"      | _                                                       || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Version"      | "3.0"                                                   || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Issuer"       | _                                                       || "SAML request is invalid - missing issuer"
        "Issuer"       | "https://example.org/metadata"                          || "SAML request is invalid - issuer not allowed"
        "Signature"    | _                                                       || "SAML request is invalid - invalid signature"
        "Signature"    | "value"                                                 || "SAML request is invalid - invalid signature"
        "SPType"       | "voluntary"                                             || "SAML request is invalid - does not conform to schema"
        "NameIDPolicy" | "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"       || "SAML request is invalid"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    def "request authentication POST with invalid saml request. #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, attributeName, attributeValue)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message"), Matchers.startsWith(message))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())

        where:
        attributeName  | attributeValue                                          || message
        "IsPassive"    | true                                                    || "SAML request is invalid - expecting IsPassive to be false"
        "ForceAuthn"   | _                                                       || "SAML request is invalid - expecting ForceAuthn to be true"
        "ForceAuthn"   | false                                                   || "SAML request is invalid - expecting ForceAuthn to be true"
        "ID"           | _                                                       || "SAML request is invalid - does not conform to schema"
        "ID"           | "31"                                                    || "SAML request is invalid - does not conform to schema"
        "IssueInstant" | _                                                       || "SAML request is invalid - does not conform to schema"
        "Version"      | _                                                       || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Version"      | "3.0"                                                   || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Issuer"       | _                                                       || "SAML request is invalid - missing issuer"
        "Issuer"       | "https://example.org/metadata"                          || "SAML request is invalid - issuer not allowed"
        "Signature"    | _                                                       || "SAML request is invalid - invalid signature"
        "Signature"    | "value"                                                 || "SAML request is invalid - invalid signature"
        "SPType"       | "voluntary"                                             || "SAML request is invalid - does not conform to schema"
        "NameIDPolicy" | "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"       || "SAML request is invalid"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    def "request authentication with missing parameters #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, attributeName, attributeValue)
        print samlRequest.size()
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())

        where:
        attributeName  | attributeValue
        "ProviderName" | "illegal-provider"
        "SPType"       | _
        "ProviderName" | _
        "ProviderName" | RandomStringUtils.random(94500, true, true)
        "IssueInstant" | "2030-11-08T19:29:47.759Z"
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_CREATE_LIGHTTOKEN")
    @Feature("AUTHENTICATION_REDIRECT_WITH_LIGHTTOKEN")
    def "request authentication with LightToken and post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")
        assertThat(lightTokenRequestUrl, Matchers.containsStringIgnoringCase("/EidasNode/SpecificConnectorRequest"))
        String htmlBody = response.getBody().prettyPrint()
        assertTrue(htmlBody.contains("</noscript>"))

        String encodedToken = response.body().htmlPath().get("**.find {it.@name == 'token'}.@value")
        String[] lightToken = new String(Base64.getDecoder().decode(encodedToken), StandardCharsets.UTF_8).split("\\|")
        assertEquals("Correct IssuerName in lightToken", "specificCommunicationDefinitionConnectorRequest", lightToken[0])
        assertTrue(SamlUtils.isValidUUID(lightToken[1]))
        assertTrue(SamlUtils.isValidDateTime(lightToken[2]))
        assertThat(Base64.getDecoder().decode(lightToken[3]).size(), Matchers.equalTo(32))
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", response.getContentType())
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_CREATE_LIGHTTOKEN")
    @Feature("AUTHENTICATION_REDIRECT_WITH_LIGHTTOKEN")
    def "request authentication redirect with LightToken and get"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        String relayState = "CDE-" + RandomStringUtils.random(76, true, true)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest, "RelayState", relayState)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        URL locationUrl = response.then().extract().response().getHeader("location").toURL()
        String[] locationQuery = locationUrl.getQuery().split("=")
        assertEquals("Correct location attribute name", "token", locationQuery[0])
        assertThat(locationUrl.getPath(), Matchers.containsStringIgnoringCase("/EidasNode/SpecificConnectorRequest"))

        String[] lightToken = new String(Base64.getDecoder().decode(locationQuery[1]), StandardCharsets.UTF_8).split("\\|")
        assertEquals("Correct IssuerName in lightToken", "specificCommunicationDefinitionConnectorRequest", lightToken[0])
        assertTrue(SamlUtils.isValidUUID(lightToken[1]))
        assertTrue(SamlUtils.isValidDateTime(lightToken[2]))
        assertThat(Base64.getDecoder().decode(lightToken[3]).size(), Matchers.equalTo(32))
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    @Feature("SECURITY")
    def "Verify authentication response header"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        response.then().header("Content-Security-Policy", Matchers.is(defaultContentSecurityPolicy))
    }
}
