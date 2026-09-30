package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static ee.ria.specificconnector.ResponseAssertions.assertErrorEnvelope
import static org.hamcrest.CoreMatchers.*
import static org.hamcrest.MatcherAssert.assertThat

class ErrorHandlingSpec extends EEConnectorSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Feature("TECHNICAL_ERRORS")
    def "handled error returns JSON even when the client asks for HTML"() {
        expect:
        Response response = Requests.request(flow, REQUEST_TYPE_GET,
                flow.domesticConnector.fullAuthenticationRequestUrl, ["Accept": "text/html"])

        assertErrorEnvelope(response, HttpStatus.SC_BAD_REQUEST, flow.domesticConnector.authenticationRequestUrl)
        assertThat("Correct message", response.body().jsonPath().getString("message"),
                equalTo("Required request parameter 'SAMLRequest' for method parameter type String is not present"))
    }

    @Feature("TECHNICAL_ERRORS")
    def "PUT on the authentication endpoint is not allowed"() {
        expect:
        Response response = Requests.request(flow, "PUT", flow.domesticConnector.fullAuthenticationRequestUrl)

        assertErrorEnvelope(response, HttpStatus.SC_METHOD_NOT_ALLOWED, flow.domesticConnector.authenticationRequestUrl)
        assertThat("Correct message", response.body().jsonPath().getString("message"),
                equalTo("Request method 'PUT' is not supported"))
    }

    @Feature("TECHNICAL_ERRORS")
    def "unmatched path returns the error envelope"() {
        expect:
        Response response = Requests.request(flow, REQUEST_TYPE_GET,
                flow.domesticConnector.fullAuthenticationRequestUrl + "/nonexistent")

        assertErrorEnvelope(response, HttpStatus.SC_NOT_FOUND,
                flow.domesticConnector.authenticationRequestUrl + "/nonexistent")
        assertThat("Correct message", response.body().jsonPath().getString("message"), equalTo("Not Found"))
    }

    @Feature("TECHNICAL_ERRORS")
    def "browser reaching the error page gets the branded page, not Whitelabel"() {
        expect:
        Response response = Requests.request(flow, REQUEST_TYPE_GET,
                flow.domesticConnector.fullAuthenticationRequestUrl + ";", ["Accept": "text/html"])

        assertThat("Correct HTTP status code is returned", response.statusCode(),
                equalTo(HttpStatus.SC_BAD_REQUEST))
        assertThat("Correct content type", response.getContentType(), startsWith("text/html"))
        assertThat("Whitelabel page is not served", response.body().asString(),
                not(containsString("Whitelabel Error Page")))
        assertThat("Branded error page is served",
                response.body().htmlPath().getString("**.find {it.@id == 'error'}"), equalTo("Bad Request"))
    }
}
