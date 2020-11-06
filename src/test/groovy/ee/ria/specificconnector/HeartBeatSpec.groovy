package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Unroll


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
        heartBeat.then()
                .body("status", Matchers.notNullValue())
                .body("name", Matchers.notNullValue())
                .body("version", Matchers.notNullValue())
                .body("commitId", Matchers.notNullValue())
                .body("commitBranch", Matchers.notNullValue())
                .body("buildTime", Matchers.notNullValue())
                .body("startTime", Matchers.notNullValue())
                .body("currentTime", Matchers.notNullValue())
                .body("dependencies[0].name", Matchers.is("igniteCluster"))
                .body("dependencies[0].status", Matchers.is("UP"))
                .body("dependencies[1].name", Matchers.is("truststore"))
                .body("dependencies[1].status", Matchers.is("UP"))
                .body("dependencies[2].name", Matchers.is("sp-eidas-eeserviceprovider-metadata"))
                .body("dependencies[2].status", Matchers.is("UP"))
                .body("dependencies[3].name", Matchers.is("connectorMetadata"))
                .body("dependencies[3].status", Matchers.is("UP"))
    }

}
