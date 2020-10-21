package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import spock.lang.Unroll

import static org.junit.Assert.assertEquals


class IdpResponseSpec extends SpecificConnectorSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    def "OIDC return state error handling"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)
        String[] elements = response.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.followRedirect(flow, elements[0]+"?"+elements[1]+state)

        assertEquals("Correct status is returned", statusCode, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", message, validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", error, validateableResponse.getBody().jsonPath().get("errors"))

        where:
        state                      || statusCode || message         || error
        "&state=some-random-state" || 400        || "Invalid state" || null
        ""                         || 400        || "Validation failed for object='idpCallbackRequest'. Error count: 1" || "Parameter 'state': must not be empty"
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return code error handling"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)
        String[] elements = response.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.followRedirect(flow, elements[0]+code+elements[2])

        assertEquals("Correct status is returned", statusCode, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", message, validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", error, validateableResponse.getBody().jsonPath().get("errors"))

        where:
        code                      || statusCode || message         || error
        "?code=some-random-code&"  || 500        || "Something went wrong internally. Please consult server logs for further details." || null
        "?"                        || 400        || "Either error or code parameter is required" || null
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return error handling on double state parameters"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)
        String[] elements = response.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.followRedirect(flow, elements[0]+"?"+elements[1]+"&"+elements[2]+"&"+elements[2])

        assertEquals("Correct status is returned", 400, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='idpCallbackRequest'. Error count: 1", validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'state': using multiple instances of parameter is not allowed", validateableResponse.getBody().jsonPath().get("errors"))
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return error handling on double code parameters"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)
        String[] elements = response.getHeader("location").split('\\?|&')

        Response validateableResponse = Requests.followRedirect(flow, elements[0]+"?"+elements[1]+"&"+elements[2]+"&"+elements[1])

        assertEquals("Correct status is returned", 400, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", "Validation failed for object='idpCallbackRequest'. Error count: 1", validateableResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", "Parameter 'code': using multiple instances of parameter is not allowed", validateableResponse.getBody().jsonPath().get("errors"))
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    def "OIDC return ignores unknown parameters"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)

        Response validateableResponse = Requests.followRedirect(flow, response.getHeader("location")+"&randomParam=someValue")

        assertEquals("Correct status is returned", 200, validateableResponse.getStatusCode())
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    def "OIDC returns usupported error on login"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        String returnUrl = taraLoginPageResponse.body().htmlPath().get("**.find {it.@class == 'link-back-mobile'}.a.@href")
        String[] elements = returnUrl.split('\\?|&')

        Response cancelResponse = Requests.backToServiceProvider(flow, elements[0]+"?"+errorCode+"&"+errorMessage+"&"+elements[3])

        assertEquals("Correct status is returned", statusCode, cancelResponse.getStatusCode())
        assertEquals("Correct message is returned", message, cancelResponse.getBody().jsonPath().get("message"))
        assertEquals("Correct error is returned", error, cancelResponse.getBody().jsonPath().get("errors"))

        where:
        errorCode           | errorMessage                        || statusCode || message         || error
        "error=hacked"      | "error_description=something+fishy" || 500        || "Something went wrong internally. Please consult server logs for further details." || null
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_INPUT_VALIDATION")
    @Feature("LOGIN_ENDPOINT_FAILED_LOGIN")
    def "OIDC returns supported error on login"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        String returnUrl = taraLoginPageResponse.body().htmlPath().get("**.find {it.@class == 'link-back-mobile'}.a.@href")
        String[] elements = returnUrl.split('\\?|&')

        Response cancelResponse = Requests.backToServiceProvider(flow, elements[0]+"?"+errorCode+"&"+errorMessage+"&"+elements[3])

        assertEquals("Correct status is returned", statusCode, cancelResponse.getStatusCode())

        where:
        errorCode           | errorMessage                        || statusCode
        "error=user_cancel" | "error_description=User+canceled+the+login+process" || 302
        "error=user_cancel" | "error_description=other+description" || 302
    }

    @Unroll
    @Feature("LOGIN_ENDPOINT_LIGHTREQUEST")
    def "OIDC return can be used only once"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response response = MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)

        Requests.followRedirect(flow, response.getHeader("location"))
        Response validateableResponse = Requests.followRedirect(flow, response.getHeader("location"))

        assertEquals("Correct status is returned", 400, validateableResponse.getStatusCode())
        assertEquals("Correct message is returned", "Invalid state", validateableResponse.getBody().jsonPath().get("message"))
    }
}
