package ee.ria.specificconnector

import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

class ServiceProviderSpec extends SpecificConnectorSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    def "Service provider request"() {
        expect:
        Response firstResponse = Requests.startingPoint(flow, "CA")

    }
}