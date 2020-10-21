package ee.ria.specificconnector

class MetadataSpec extends SpecificConnectorSpecification {
    Flow flow = new Flow(props)

    def "Metadata has valid signature"() {
        expect:
        MetadataUtils.validateMetadataSignature(Requests.getMetadataBody(flow))
    }
}