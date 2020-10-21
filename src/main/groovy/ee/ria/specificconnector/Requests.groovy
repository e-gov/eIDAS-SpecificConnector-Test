package ee.ria.specificconnector

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.response.Response

import static io.restassured.RestAssured.config
import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class Requests {
    @Step("Get metadata")
    static String getMetadataBody(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.connector.fullMetadataUrl)
                .then()
                .statusCode(200)
                .extract().body().asString()
    }

    @Step("Get heartbeat")
    static Response getHeartbeat(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.connector.fullheartbeatUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Open authentication page")
    static Response getAuthenticationPage(Flow flow, String samlRequest) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("SAMLRequest", samlRequest)
                        .formParam("RelayState", "")
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(flow.specificProxyService.fullAuthenticationRequestUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Proxy Service Request")
    static Response proxyServiceRequest(Flow flow, String action, String token) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("token", token)

                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(action)
                        .then()
                        .extract().response()
        return response
    }

    @Step("TARA redirect Request")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("{flow.endUser}Follow OpenID Connect Authentication request redirect")
    static Response followTARARedirect(Flow flow, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Consent Submit")
    static Response consentSubmit(Flow flow, String token) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("token", token)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Consent Cancel")
    static Response consentCancel(Flow flow, String token) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("token", token)
                        .queryParam("cancel", true)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Return to service provider without authentication")
    static Response backToServiceProvider(Flow flow, String url) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(url)
                        .then()
                        .extract().response()
        return response
    }

    @Step("First page")
    static Response startingPoint(Flow flow, String country) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("Country", country)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(flow.specificProxyService.fullConsentUrl)
                        .then()
                        .extract().response()
        return response
    }
}
