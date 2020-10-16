package ee.ria.specificconnector.tara


import ee.ria.specificconnector.Flow
import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.response.Response
import org.joda.time.DateTime

import static io.restassured.RestAssured.given

class MobileId {
    @Step("Authenticates with Mobile-ID")
    static Response authenticateWithMobileId(Flow flow, Response taraLoginPageResponse, String mobileNo, String idCode, Integer pollMillis) throws InterruptedException, URISyntaxException, IOException {
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        Response submitResponse = submitMobileIdLogin(flow, mobileNo, idCode, execution, flow.specificProxyService.getTaraLoginPageUrl())
        String execution2 = submitResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        Response pollResponse = pollForAuthentication(flow, execution2, flow.specificProxyService.getTaraLoginPageUrl(), pollMillis)
        return Oidc.followLoginRedirects(flow, pollResponse.getHeader("location"))
    }


    @Step("Submit Mobile-ID login")
    static Response submitMobileIdLogin(Flow flow, String mobileNo, String idCode, String execution, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .formParam("execution", execution)
                .formParam("_eventId", "submit")
                .formParam("idlang", "")
                .formParam("geolocation", "")
                .formParam("principalCode", idCode)
                .formParam("mobileNumber", mobileNo)
                .when()
                .post(location)
                .then()
                .extract().response()
    }

    @Step("Poll Mobile-ID authentication")
    static Response pollForAuthentication(Flow flow, String execution, String location, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 4 + 200)
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis)
            Response response = given()
                    .filter(flow.getCookieFilter())
                    .filter(new AllureRestAssured())
                    .relaxedHTTPSValidation()
                    .redirects().follow(false)
                    .formParam("execution", execution)
                    .formParam("_eventId", "check")
                    //.queryParam("client_id", flow.getRelyingParty().getClientId())
                    //.queryParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                    .when()
                    .post(location)
                    .then()
                    .extract().response()
            if (response.statusCode() == 302) {
                return response
            }
        }
        throw new RuntimeException("No MID response in: " + (intervalMillis * 4 + 200) + " millis")
    }
/*
    @Step("Cancel Mobile-ID authentication")
    public static Response cancelAuthentication(Flow flow, String execution) throws InterruptedException {

        Response response = given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .formParam("execution", execution)
                .formParam("_eventId", "cancel")
                //.queryParam("client_id", flow.getRelyingParty().getClientId())
                //.queryParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                //.when()
                //.post(flow.getOpenIDProvider().getLoginUrl())
                //.then()
        //.extract().response();
        return response;
    }

 */
}
