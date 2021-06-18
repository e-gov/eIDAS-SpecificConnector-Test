package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Unroll

import static org.junit.Assert.assertThat

class HeartBeatSpec extends EEConnectorSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("HEALTH_MONITORING_ENDPOINT_DEPENDENCIES")
    def "Verify heartbeat response elements"() {
        expect:
        Response heartBeat = Requests.getHeartbeat(flow)

        assertThat(heartBeat.body().jsonPath().get("status").toString(), Matchers.equalTo("UP"))
        assertThat(heartBeat.body().jsonPath().get("name"), Matchers.notNullValue())
        assertThat(heartBeat.body().jsonPath().get("version"), Matchers.notNullValue())
        assertThat(heartBeat.body().jsonPath().get("commitId"), Matchers.notNullValue())
        assertThat(heartBeat.body().jsonPath().get("commitBranch"), Matchers.notNullValue())
        assertThat(heartBeat.body().jsonPath().get("buildTime"), Matchers.notNullValue())
        assertThat(heartBeat.body().jsonPath().get("startTime"), Matchers.notNullValue())
        assertThat(heartBeat.body().jsonPath().get("currentTime"), Matchers.notNullValue())
        assertThat(heartBeat.body().jsonPath().get("dependencies.name"), Matchers.hasItem("igniteCluster"))
        assertThat(heartBeat.body().jsonPath().get("dependencies.name"), Matchers.hasItem("truststore"))
    }

    @Unroll
    @Feature("HEALTH_MONITORING_ENDPOINT")
    @Feature("SECURITY")
    def "Verify heartbeat response header"() {
        expect:
        Response heartBeat = Requests.getHeartbeat(flow)
        heartBeat.then().header("Content-Security-Policy", Matchers.is(defaultContentSecurityPolicy))
    }

}
