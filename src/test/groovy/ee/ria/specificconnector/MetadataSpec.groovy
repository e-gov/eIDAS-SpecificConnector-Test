package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.internal.matcher.xml.XmlXsdMatcher
import io.restassured.path.xml.XmlPath

import io.restassured.response.ValidatableResponse
import org.hamcrest.Matchers
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

import static org.hamcrest.Matchers.containsString
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import spock.lang.Unroll

import static org.junit.Assert.assertTrue


class MetadataSpec extends EEConnectorSpecification {
    Flow flow = new Flow(props)

    @Unroll
    @Feature("SP_METADATA_SIGNING")
    @Feature("METADATA_REQUEST")
    def "Metadata has valid signature"() {
        expect:
        MetadataUtils.validateMetadataSignature(Requests.getMetadataBody(flow))
    }

    @Unroll
    @Feature("SP_METADATA_RESPONSE")
    def "Metadata XML schema validation"() {
        expect:
        ValidatableResponse validatableResponse = Requests.getMetadataResponse(flow)
        validatableResponse.assertThat().body(XmlXsdMatcher.matchesXsd(new File("src/test/resources/saml-schema-metadata-2.0.xsd")))
    }

    @Unroll
    @Feature("SP_METADATA_VALID_UNTIL")
    def "Metadata xml check"() {
        expect:
        String metadataXml = Requests.getMetadataBody(flow)
        XmlPath xmlPath = new XmlPath(metadataXml)

        String validUntil = xmlPath.getString("EntityDescriptor.@validUntil")
        def timestamp = ZonedDateTime.parse(validUntil, DateTimeFormatter.ISO_DATE_TIME)
        def tomorrow = ZonedDateTime.now(ZoneId.of("UTC")).plusDays(1L)
        def duration = timestamp >> tomorrow
        assertTrue(Math.abs(duration.seconds) < 15)

        String foreignCountry = xmlPath.getString("EntityDescriptor.Extensions.SupportedMemberStates.MemberState")
        assertThat(foreignCountry, containsString("CA"))
    }

    @Unroll
    @Feature("SP_METADATA_CONTACT_INFO")
    @Feature("SP_METADATA_EXTENSIONS_REQUESTERID")
    def "Metadata contact info validation"() {
        expect:
        String metadataXml = Requests.getMetadataBody(flow)
        XmlPath xmlPath = new XmlPath(metadataXml)
        String spType = xmlPath.getString("EntityDescriptor.Extensions.SPType")
        String requesterIdFlag = xmlPath.getString("EntityDescriptor.Extensions.EntityAttributes.Attribute.AttributeValue");
        String organization = xmlPath.getString("EntityDescriptor.Organization")
        String support = xmlPath.getString("**.find {it.@contactType == 'support'}")
        String technical = xmlPath.getString("**.find {it.@contactType == 'technical'}")

        assertThat(spType, Matchers.emptyString())
        assertThat(requesterIdFlag, Matchers.equalTo("http://eidas.europa.eu/entity-attributes/termsofaccess/requesterid"))
        assertThat(organization, Matchers.equalTo("Estonian Information System AuthorityRIAhttps://www.ria.ee"))
        assertThat(support, Matchers.equalTo("RIADeskHelphelp@ria.ee+372 663 0230"))
        assertThat(technical, Matchers.equalTo("RIADeskHelphelp@ria.ee+372 663 0230"))
    }

    @Unroll
    @Feature("SP_METADATA_SUPPORTED_BINDINGS")
    @Feature("SP_METADATA_SUPPORTED_ATTRIBUTES")
    def "Metadata default attributes and bindings"() {
        expect:
        String metadataXml = Requests.getMetadataBody(flow)
        XmlPath xmlPath = new XmlPath(metadataXml)
        String postBinding = xmlPath.get("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Binding")[0]
        String redirectBinding = xmlPath.get("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Binding")[1]
        String postLocation = xmlPath.get("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Location")[0]
        String redirectLocation = xmlPath.get("EntityDescriptor.IDPSSODescriptor.SingleSignOnService.@Location")[1]
        assertEquals("Correct post Binding attribute value", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", postBinding)
        assertEquals("Correct redirect Binding attribute value", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", redirectBinding)
        assertEquals("Correct post binding Location attribute value", flow.domesticConnector.fullAuthenticationRequestUrlWithoutPort.toString(), postLocation)
        assertEquals("Correct post binding Location attribute value", flow.domesticConnector.fullAuthenticationRequestUrlWithoutPort.toString(), redirectLocation)

        String personIdentifier = xmlPath.getString("**.find {it.@FriendlyName == 'PersonIdentifier'}.@Name")
        String familyName = xmlPath.getString("**.find {it.@FriendlyName == 'FamilyName'}.@Name")
        String firstName = xmlPath.getString("**.find {it.@FriendlyName == 'FirstName'}.@Name")
        String dateOfBirth = xmlPath.getString("**.find {it.@FriendlyName == 'DateOfBirth'}.@Name")
        assertEquals("Correct PersonIdentifier SAML attribute", "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", personIdentifier)
        assertEquals("Correct FamilyName SAML attribute", "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", familyName)
        assertEquals("Correct FirstName SAML attribute", "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName", firstName)
        assertEquals("Correct DateOfBirth SAML attribute", "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth", dateOfBirth)
    }

    @Unroll
    @Feature("METADATA_REQUEST")
    @Feature("SECURITY")
    def "Verify metadata response header"() {
        expect:
        ValidatableResponse response = Requests.getMetadataResponse(flow)
        response.header("Content-Security-Policy", Matchers.is(defaultContentSecurityPolicy))
    }

}