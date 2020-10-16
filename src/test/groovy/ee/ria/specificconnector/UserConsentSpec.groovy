package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Ignore
import spock.lang.Unroll

import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig
import static org.junit.Assert.assertEquals

class UserConsentSpec extends SpecificConnectorSpecification {
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
    @Feature("CONSENT_VIEW")
    def "Proper information is shown in consent view"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, spName)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)

        String some = consentPageResponse.body().htmlPath().get("**.find {it.@id == 'LoA'}")
        assertEquals("Correct service provider is returned", spName, consentPageResponse.body().htmlPath().get("**.find {it.@id == 'spId'}"))
//        assertEquals("Correct LOA is returned", loa_level, consentPageResponse.body().htmlPath().get("**.find {it.@id == 'LoA'}").toString().trim())
        assertEquals("Correct ID code is returned", personalNumber, consentPageResponse.body().htmlPath().get("**.find {it.@id == 'PersonIdentifier'}").toString().trim())
        assertEquals("Correct family name is returned", familyName, consentPageResponse.body().htmlPath().get("**.find {it.@id == 'FamilyName'}").toString().trim())
        assertEquals("Correct first name is returned", firstName, consentPageResponse.body().htmlPath().get("**.find {it.@id == 'FirstName'}").toString().trim())
        assertEquals("Correct birth date is returned", dateOfBirth, consentPageResponse.body().htmlPath().get("**.find {it.@id == 'DateOfBirth'}").toString().trim())

        where:
        spName       || familyName                   || firstName  || personalNumber      || dateOfBirth  || loa_level
        "DEMO-SP-CA" || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN" || "60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    def "Invalid consent token: #token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)

        Response response = Requests.consentSubmit(flow, token)

        assertEquals("Correct status code is returned", statusCode, response.getStatusCode())
        assertEquals("Correct message is returned", message, response.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", errors, response.getBody().jsonPath().get("errors"))

        where:
        token                   || statusCode || message || errors
        "#¤õs"                  || 400        || "Validation failed for object='requestParameters'. Error count: 1" || "Parameter 'token[0]': only base64 characters allowed"
        "thisIsNotCorrectToken" || 400        || "Invalid token" || null
    }

    @Ignore ("TARA2-95 After fix merge this test to: Error handling on ProxyServiceRequest with invalid token: #token ")
    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    def "Consent submit with empty token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        String consentToken = ""

        Response response = Requests.consentSubmit(flow, consentToken)

        assertEquals("Correct status code is returned", 400, response.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='requestParameters'. Error count: 1", response.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'token': exceeds max length", response.getBody().jsonPath().get("errors"))
    }

    @Unroll
    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    def "Consent submit with invalid token format"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)

        Response response = Requests.consentSubmit(flow, token)

        assertEquals("Correct status code is returned", statusCode, response.getStatusCode())
        assertEquals("Correct message is returned", message, response.getBody().jsonPath().get("message"))

        where:
        token                   || statusCode || message
        "c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGl8b25Db25uZWN0b3JSZXF1ZXN0fDg1MmE2NGMwLThhYzEtNDQ1Zi1iMGUxLTk5MmFkYTQ5MzAzM3wyMDE3LTEyLTExIDE0OjEyOjA1IDE0OHw3TThwK3VQOENLWHVNaTJJcVNkYTF0ZzQ1MldsUnZjT1N3dTBkY2lzU1lFPQ"      || 400  || "Invalid token"
        "c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGl8IG9uQ29ubmVjdG9yUmVxdWVzdHwgODUyYTY0YzAtOGFjMS00NDVmLWIwZTEtOTkyYWRhNDkzMDMzIHwgMjAxNy0xMi0xMSAxNDoxMjowNSAxNDh8N004cCt1UDhDS1h1TWkySXFTZGExdGc0NTJXbFJ2Y09Td3UwZGNpc1NZRT0" || 400  || "Invalid token"
    }

    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    def "Consent token missing"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)

        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()

        assertEquals("Correct status code is returned", 400, response.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='requestParameters'. Error count: 1", response.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'token': must not be null", response.getBody().jsonPath().get("errors"))
    }

    @Ignore ("TARA2-95")
    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    def "Consent token too long"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        String consentToken = "a"*1001

        Response response = Requests.consentSubmit(flow, consentToken)

        assertEquals("Correct status code is returned", 400, response.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='requestParameters'. Error count: 1", response.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'token': exceeds max length", response.getBody().jsonPath().get("errors"))
    }

    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    def "Error handling on double token"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        String consentToken = response.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.input[0].@value")
        Response response1 =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("token", consentToken)
                        .queryParam("token", consentToken)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()

        assertEquals("Correct status code is returned", 400, response1.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='requestParameters'. Error count: 1", response1.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'token': using multiple instances of parameter is not allowed", response1.getBody().jsonPath().get("errors"))
    }

    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    def "Additional parameters are ignored"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        String consentToken = response.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.input[0].@value")
        Response response1 =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("token", consentToken)
                        .queryParam("someExtra", true)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()

        assertEquals("Correct status code is returned", 302, response1.getStatusCode())
    }

    @Feature("CONSENT_ENDPOINT_INPUT_VALIDATION")
    @Feature("CONSENT_ENDPOINT_USER_AGREE")
    def "Usage of optional cancel variable"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        String consentToken = response.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.input[0].@value")
        Response response1 =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("token", consentToken)
                        .queryParam("cancel", false)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()

        assertEquals("Correct status code is returned", 302, response1.getStatusCode())
    }
}

