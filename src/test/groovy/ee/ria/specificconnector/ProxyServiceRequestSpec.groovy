package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.NameIDType
import spock.lang.Ignore
import spock.lang.Unroll

import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig
import static org.junit.Assert.assertEquals

class ProxyServiceRequestSpec extends SpecificConnectorSpecification {
    public static final String FN_DATE = "DateOfBirth"
    public static final String FN_PNO = "PersonIdentifier"
    public static final String FN_FAMILY = "FamilyName"
    public static final String FN_FIRST = "FirstName"

    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    @Feature("AUTHENTICATION_REQUEST_LIGHTTOKEN_ACCEPTANCE")
    def "Error handling on ProxyServiceRequest with invalid token: #token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)

        assertEquals("Correct status code is returned", statusCode, response2.getStatusCode())
        assertEquals("Correct message is returned", message, response2.getBody().jsonPath().get("message"))

        where:
        token                   || statusCode || message
        "#¤õs"                  || 400        || "Validation failed for object='requestParameters'. Error count: 1"
        "thisIsNotCorrectToken" || 400        || "Invalid token"
    }

    @Ignore ("TARA2-95 After fix merge this test to: Error handling on ProxyServiceRequest with invalid token: #token ")
    @Unroll
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    @Feature("AUTHENTICATION_REQUEST_LIGHTTOKEN_ACCEPTANCE")
    def "Error handling on ProxyServiceRequest with empty token: #token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)

        assertEquals("Correct status code is returned", statusCode, response2.getStatusCode())
        assertEquals("Correct message is returned", message, response2.getBody().jsonPath().get("message"))

        where:
        token                   || statusCode || message
        ""                      || 400        || "Validation failed for object='requestParameters'. Error count: 1"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_LIGHTTOKEN_ACCEPTANCE")
    def "Error handling on ProxyServiceRequest with invalid token format"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)

        assertEquals("Correct status code is returned", statusCode, response2.getStatusCode())
        assertEquals("Correct message is returned", message, response2.getBody().jsonPath().get("message"))

        where:
        token                   || statusCode || message
        "c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGl8b25Db25uZWN0b3JSZXF1ZXN0fDg1MmE2NGMwLThhYzEtNDQ1Zi1iMGUxLTk5MmFkYTQ5MzAzM3wyMDE3LTEyLTExIDE0OjEyOjA1IDE0OHw3TThwK3VQOENLWHVNaTJJcVNkYTF0ZzQ1MldsUnZjT1N3dTBkY2lzU1lFPQ"      || 400  || "Invalid token"
        "c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGl8IG9uQ29ubmVjdG9yUmVxdWVzdHwgODUyYTY0YzAtOGFjMS00NDVmLWIwZTEtOTkyYWRhNDkzMDMzIHwgMjAxNy0xMi0xMSAxNDoxMjowNSAxNDh8N004cCt1UDhDS1h1TWkySXFTZGExdGc0NTJXbFJ2Y09Td3UwZGNpc1NZRT0" || 400  || "Invalid token"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    def "Error handling on missing token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")

        Response response2 =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(action)
                        .then()
                        .extract().response()

        assertEquals("Correct status code is returned", 400, response2.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='requestParameters'. Error count: 1", response2.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'token': must not be null", response2.getBody().jsonPath().get("errors"))
    }

    @Ignore ("TARA2-95")
    @Unroll
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    def "Error handling on over max length token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = "a"*1001

        Response response2 = Requests.proxyServiceRequest(flow, action, token)

        assertEquals("Correct status code is returned", 400, response2.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='requestParameters'. Error count: 1", response2.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'token': exceeds max length", response2.getBody().jsonPath().get("errors"))
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_PROXY_ENDPOINT")
    def "Error handling on double token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response2 =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("token", token)
                        .formParam("token", token)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(action)
                        .then()
                        .extract().response()

        assertEquals("Correct status code is returned", 400, response2.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='requestParameters'. Error count: 1", response2.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'token': using multiple instances of parameter is not allowed", response2.getBody().jsonPath().get("errors"))
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SPTYPE")
    def "request authentication with supported SPType: #spType"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA","http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM, NameIDType.UNSPECIFIED, spType)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(assertion))
        assertEquals("Correct family name is returned", familyName, SamlUtils.getAttributeValue(assertion, FN_FAMILY))
        assertEquals("Correct first name is returned", firstName, SamlUtils.getAttributeValue(assertion, FN_FIRST))
        assertEquals("Correct id code is returned", personalNumber, SamlUtils.getAttributeValue(assertion, FN_PNO))
        assertEquals("Correct birth date is returned", dateOfBirth, SamlUtils.getAttributeValue(assertion, FN_DATE))

        where:
        spType         ||  familyName                  || firstName  || personalNumber      || dateOfBirth  || loa_level
        "public"       || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SPTYPE")
    @Feature("PROCESS_ERRORS")
    def "request authentication with not supported SPType: #spType"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA","http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM, NameIDType.UNSPECIFIED, spType)

        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)
        response2.then().statusCode(302)

        String taraUrl =  response2.then().extract().response().getHeader("location")

        Response authenticationResponse = Requests.followRedirect(flow, taraUrl)

        org.opensaml.saml.saml2.core.Response samlResponseObj = SamlResponseUtils.getSamlResponseFromResponse(authenticationResponse)

        assertEquals("The request could not be performed due to an error on the part of the requester.", samlStatusCode, samlResponseObj.status.statusCode.value)
        assertEquals("The SAML responder or SAML authority is able to process the request but has chosen not to respond.", samlSubStatusCode, samlResponseObj.status.statusCode.statusCode.value)
        assertEquals("Reason for unsuccessful authentication.", samlStatusMessage, samlResponseObj.status.statusMessage.message)

        where:
        spType         || samlStatusCode                                 || samlSubStatusCode                                  || samlStatusMessage
        "private"      || "urn:oasis:names:tc:SAML:2.0:status:Requester" || "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" || "Service provider type not supported. Allowed types: [public]"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SPTYPE")
    @Feature("TECHNICAL_ERRORS")
    def "request authentication with invalid SPType: #spType"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA","http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM, NameIDType.UNSPECIFIED, spType)

        Response response = Requests.getAuthenticationPage(flow, samlRequest)

        assertEquals("Error is returned", errorResponse, response.body().htmlPath().get("**.find {it.@class == 'sub-title'}").toString())


        where:
        spType         || errorResponse
        "notProvided"  || "An unexpected error has occurred"
        ""             || "An unexpected error has occurred"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_LEGAL_PERSON")
    @Feature("TECHNICAL_ERRORS")
    def "request authentication with legal attributes is currently not supported"() {
        expect:
        String samlRequest = Steps.getLegalPersonAuthnRequest(flow, "DEMO-SP-CA")
        Response response = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response errorResponse = Requests.proxyServiceRequest(flow, action, token)

        assertEquals("Status 400 is returned", 400, errorResponse.statusCode())
        assertEquals("Status message is returned", "Support for legal person attributes has been temporarily suspended", errorResponse.body().jsonPath().get("message"))
    }
}
