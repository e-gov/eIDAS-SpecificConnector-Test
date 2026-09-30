package ee.ria.specificconnector

import io.qameta.allure.Step
import io.restassured.response.Response
import org.apache.http.HttpStatus

import static org.hamcrest.CoreMatchers.endsWith
import static org.hamcrest.CoreMatchers.equalTo
import static org.hamcrest.CoreMatchers.notNullValue
import static org.hamcrest.MatcherAssert.assertThat

class ResponseAssertions {

    private static final Map<Integer, String> REASON_PHRASE = [
            (HttpStatus.SC_BAD_REQUEST)          : "Bad Request",
            (HttpStatus.SC_NOT_FOUND)            : "Not Found",
            (HttpStatus.SC_METHOD_NOT_ALLOWED)   : "Method Not Allowed",
            (HttpStatus.SC_INTERNAL_SERVER_ERROR): "Internal Server Error",
    ]

    @Step("Verify error envelope: {status}")
    static void assertErrorEnvelope(Response response, int status, String pathSuffix) {
        assertThat("Correct HTTP status code is returned", response.statusCode(), equalTo(status))
        assertThat("Correct content type", response.getContentType(), equalTo("application/json"))
        assertThat("Correct error", response.body().jsonPath().getString("error"), equalTo(REASON_PHRASE[status]))
        assertThat("Correct status in body", response.body().jsonPath().getInt("status"), equalTo(status))
        assertThat("Correct path", response.body().jsonPath().getString("path"), endsWith(pathSuffix))
        assertThat("Incident number is present", response.body().jsonPath().get("incidentNumber"), notNullValue())
    }

    @Step("Verify security headers")
    static void assertSecurityHeaders(Response response) {
        assertThat("Correct X-Content-Type-Options", response.getHeader("X-Content-Type-Options"), equalTo("nosniff"))
        assertThat("Correct X-Frame-Options", response.getHeader("X-Frame-Options"), equalTo("DENY"))
        assertThat("Correct X-XSS-Protection", response.getHeader("X-XSS-Protection"), equalTo("1; mode=block"))
        assertThat("Correct Cache-Control", response.getHeader("Cache-Control"), equalTo("no-cache, no-store, max-age=0, must-revalidate"))
        assertThat("Correct Pragma", response.getHeader("Pragma"), equalTo("no-cache"))
    }
}
