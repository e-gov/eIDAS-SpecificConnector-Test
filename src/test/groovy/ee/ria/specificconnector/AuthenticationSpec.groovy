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
        assertEquals("Correct HTTP status code is returned", 200, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
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
        assertEquals("Correct HTTP status code is returned", 302, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    def "request authentication with multiple instances"() {
        expect:
        Response response = Requests.getAuthenticationPageWithDuplicateParams(flow, REQUEST_TYPE_POST, "1234567", additionalParam, "78901234")
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
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
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        def map = [:]
        // Spock specific workaround
        def map1 = SamlUtils.setUrlParameter(map, param1, samlRequest)
        def map2 = SamlUtils.setUrlParameter(map, param2, param2Value)
        def map3 = SamlUtils.setUrlParameter(map, param3, param3Value)
        def map4 = SamlUtils.setUrlParameter(map, param4, param4Value)

        Response response = Requests.getAuthenticationPageWithParameters(flow, REQUEST_TYPE_POST, map)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message"), Matchers.startsWith(message))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())

        where:
        param1        || param2 || param2Value || param3 || param3Value || param4 || param4Value || statusCode || message
        _             || _ || _ || _ || _ || _  || _ || 400 || "Required String parameter 'SAMLRequest' is not present"
        "SAMLRequest" || _ || _ || _ || _ || _  || _ || 400 || "Required String parameter 'country' is not present"
        "SAMLRequest" || "country" || _ || _ || _ || _  || _ || 400 || "post.country: must match "
        "SAMLRequest" || "country" || "CAA" || _ || _ || _  || _ || 400 || "post.country: must match "
        "SAMLRequest" || "country" || "CA" || "RelayState" || "1XyyAocKwZp8Zp8qd9lhVKiJPF1AywyfpXTLqYGLFE73CKcEgSKOrfVq9UMfX9HAfWwBJMI9O7Bm22BZ1" || _  || _ || 400 || "post.RelayState: must match"
        "SAMLRequest" || "country" || "CA" || "RelayState" || "\b\f" || _  || _ || 400 || "post.RelayState: must match"
        _             || "SAMLRequest" || "Ää" || "country" || "CA" || _  || _ || 400 || "Invalid saml request format"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SP_CHECK")
    def "request authentication with invalid service provider"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithInvalidIssuer(flow, "eidas-eeserviceprovider")
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("SAML request is invalid - issuer not allowed"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with missing attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithoutExtensions(flow, "eidas-eeserviceprovider")
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("SAML request is invalid - no requested attributes"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with unsupported attribute"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithUnsupportedAttribute(flow, "eidas-eeserviceprovider")
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("SAML request is invalid - unsupported requested attributes"))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with invalid signing certificate #credential.entityId"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithInvalidCredential(flow, "eidas-eeserviceprovider", credential)
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
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
    def "request authentication with invalid saml request. #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, "eidas-eeserviceprovider", attributeName, attributeValue)
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("message"), Matchers.startsWith(message))
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())

        // TODO correct messages here when API fixed
        where:
        attributeName  || attributeValue                                          || message
        "IsPassive"    || _                                                       || "SAML request is invalid IsPassive"
        "IsPassive"    || true                                                    || "SAML request is invalid IsPassive"
        "Destination"  || _                                                       || "SAML request is invalid Destination"
        "Destination"  || "https://example.net/SpecificConnector/ServiceProvider" || "SAML request is invalid Destination"
        "ForceAuthn"   || _                                                       || "SAML request is invalid ForceAuthn"
        "ForceAuthn"   || false                                                   || "SAML request is invalid ForceAuthn"
        "ID"           || _                                                       || "SAML request is invalid - does not conform to schema"
        "ID"           || "31"                                                    || "SAML request is invalid - does not conform to schema"
        "IssueInstant" || _                                                       || "SAML request is invalid - does not conform to schema"
        "IssueInstant" || "2030-11-08T19:29:47.759Z"                              || "SAML request is invalid"
        "ProviderName" || _                                                       || "SAML request is invalid"
        "Version"      || _                                                       || "SAML request is invalid @Version"
        "Version"      || "3.0"                                                   || "SAML request is invalid @Version"
        "Issuer"       || _                                                       || "SAML request is invalid saml2:Issuer"
        "Issuer"       || "https://example.org/metadata"                          || "SAML request is invalid - issuer not allowed"
        "Signature"    || _                                                       || "SAML request is invalid - invalid signature"
        "Signature"    || "value"                                                 || "SAML request is invalid - invalid signature"
        "SPType"       || "voluntary"                                             || "SAML request is invalid - does not conform to schema"
        "NameIDPolicy" || "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"       || "SAML request is invalid"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    def "request authentication with missing parameters #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, "eidas-eeserviceprovider", attributeName, attributeValue)
        Response response = Requests.getAuthenticationPage(flow, REQUEST_TYPE_GET, samlRequest)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())

        where:
        attributeName  || attributeValue     || message
        "ProviderName" || "illegal-provider" || "SAML request is invalid"
        "SPType"       || _                  || "SAML request is invalid eidas:SPType"

    }
}
