package ee.ria.specificconnector;

import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.Signer;

import javax.xml.namespace.QName;


public class RequestBuilderUtils extends ResponseAssertionBuilderUtils {

    public AuthnRequest buildLegalAuthnRequest(Credential signCredential, String providerName, String destination, String consumerServiceUrl, String issuerValue, String loa) {
        try {
            Signature signature = prepareSignature(signCredential);
            DateTime timeNow = new DateTime();
            AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
            authnRequest.setIssueInstant(timeNow);
            authnRequest.setForceAuthn(true);
            authnRequest.setIsPassive(false);
            authnRequest.setProviderName(providerName);
            authnRequest.setDestination(destination);
            authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            authnRequest.setAssertionConsumerServiceURL(consumerServiceUrl);
            authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
            authnRequest.setIssuer(buildIssuer(issuerValue));
            authnRequest.setNameIDPolicy(buildNameIdPolicy(NameIDType.UNSPECIFIED));
            authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext(loa, AuthnContextComparisonTypeEnumeration.MINIMUM));
            authnRequest.setExtensions(buildLegalExtensions());
            authnRequest.setSignature(signature);
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
            Signer.signObject(signature);

            return authnRequest;
        } catch (Exception e) {
            throw new RuntimeException("SAML error:" + e.getMessage(), e);
        }
    }

    public AuthnRequest buildAuthnRequestParams(Credential signCredential, String providerName, String destination, String consumerServiceUrl, String issuerValue, String loa, AuthnContextComparisonTypeEnumeration comparison, String nameId, String spType) {
        try {
            Signature signature = prepareSignature(signCredential);
            DateTime timeNow = new DateTime();
            AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
            authnRequest.setIssueInstant(timeNow);
            authnRequest.setForceAuthn(true);
            authnRequest.setIsPassive(false);
            authnRequest.setProviderName(providerName);
            authnRequest.setDestination(destination);
            authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            authnRequest.setAssertionConsumerServiceURL(consumerServiceUrl);
            authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
            authnRequest.setIssuer(buildIssuer(issuerValue));
            if (nameId != null && !nameId.isBlank()) {
                authnRequest.setNameIDPolicy(buildNameIdPolicy(nameId));
            }
            authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext(loa, comparison));
            authnRequest.setExtensions(buildExtensions(spType));
            authnRequest.setSignature(signature);
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
            Signer.signObject(signature);

            return authnRequest;
        } catch (Exception e) {
            throw new RuntimeException("SAML error:" + e.getMessage(), e);
        }
    }

    public AuthnRequest buildAuthnRequestParamsWithoutExtensions(Credential signCredential, String providerName, String destination, String consumerServiceUrl, String issuerValue, String loa, AuthnContextComparisonTypeEnumeration comparison, String nameId, String spType) {
        try {
            Signature signature = prepareSignature(signCredential);
            DateTime timeNow = new DateTime();
            AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
            authnRequest.setIssueInstant(timeNow);
            authnRequest.setForceAuthn(true);
            authnRequest.setIsPassive(false);
            authnRequest.setProviderName(providerName);
            authnRequest.setDestination(destination);
            authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            authnRequest.setAssertionConsumerServiceURL(consumerServiceUrl);
            authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
            authnRequest.setIssuer(buildIssuer(issuerValue));
            if (nameId != null && !nameId.isBlank()) {
                authnRequest.setNameIDPolicy(buildNameIdPolicy(nameId));
            }
            authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext(loa, comparison));
            authnRequest.setExtensions(buildEmptyExtensions(spType));
            authnRequest.setSignature(signature);
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
            Signer.signObject(signature);

            return authnRequest;
        } catch (Exception e) {
            throw new RuntimeException("SAML error:" + e.getMessage(), e);
        }
    }

    public AuthnRequest buildAuthnRequestParamsWithUnsupportedAttribute(Credential signCredential, String providerName, String destination, String consumerServiceUrl, String issuerValue, String loa, AuthnContextComparisonTypeEnumeration comparison, String nameId, String spType) {
        try {
            Signature signature = prepareSignature(signCredential);
            DateTime timeNow = new DateTime();
            AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
            authnRequest.setIssueInstant(timeNow);
            authnRequest.setForceAuthn(true);
            authnRequest.setIsPassive(false);
            authnRequest.setProviderName(providerName);
            authnRequest.setDestination(destination);
            authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            authnRequest.setAssertionConsumerServiceURL(consumerServiceUrl);
            authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
            authnRequest.setIssuer(buildIssuer(issuerValue));
            if (nameId != null && !nameId.isBlank()) {
                authnRequest.setNameIDPolicy(buildNameIdPolicy(nameId));
            }
            authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext(loa, comparison));
            authnRequest.setExtensions(buildExtensionsWithUnsupportedAttribute(spType));
            authnRequest.setSignature(signature);
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest).marshall(authnRequest);
            Signer.signObject(signature);

            return authnRequest;
        } catch (Exception e) {
            throw new RuntimeException("SAML error:" + e.getMessage(), e);
        }
    }

    private Extensions buildExtensions(String spTypeExtension) {
        Extensions extensions = OpenSAMLUtils.buildSAMLObject(Extensions.class);

        XSAny spType = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "SPType", "eidas");
        spType.setTextContent(spTypeExtension);
        extensions.getUnknownXMLObjects().add(spType);

        XSAny requestedAttributes = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");

        requestedAttributes.getUnknownXMLObjects().add(buildRequestedAttribute("PersonIdentifier", "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", true));
        requestedAttributes.getUnknownXMLObjects().add(buildRequestedAttribute("FamilyName", "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", true));
        requestedAttributes.getUnknownXMLObjects().add(buildRequestedAttribute("FirstName", "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", true));
        requestedAttributes.getUnknownXMLObjects().add(buildRequestedAttribute("DateOfBirth", "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", true));

        extensions.getUnknownXMLObjects().add(requestedAttributes);

        return extensions;
    }

    private Extensions buildEmptyExtensions(String spTypeExtension) {
        Extensions extensions = OpenSAMLUtils.buildSAMLObject(Extensions.class);

        XSAny spType = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "SPType", "eidas");
        spType.setTextContent(spTypeExtension);
        extensions.getUnknownXMLObjects().add(spType);

        XSAny requestedAttributes = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");
        extensions.getUnknownXMLObjects().add(requestedAttributes);
        return extensions;
    }

    private Extensions buildExtensionsWithUnsupportedAttribute(String spTypeExtension) {
        Extensions extensions = OpenSAMLUtils.buildSAMLObject(Extensions.class);

        XSAny spType = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "SPType", "eidas");
        spType.setTextContent(spTypeExtension);
        extensions.getUnknownXMLObjects().add(spType);

        XSAny requestedAttributes = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");

        requestedAttributes.getUnknownXMLObjects().add(buildRequestedAttribute("RepresentativePersonIdentifier", "http://eidas.europa.eu/attributes/naturalperson/representative/PersonIdentifier", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", true));
        extensions.getUnknownXMLObjects().add(requestedAttributes);
        return extensions;
    }

    private Extensions buildLegalExtensions() {
        Extensions extensions = OpenSAMLUtils.buildSAMLObject(Extensions.class);

        XSAny spType = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "SPType", "eidas");
        spType.setTextContent("public");
        extensions.getUnknownXMLObjects().add(spType);

        XSAny requestedAttributes = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");

        requestedAttributes.getUnknownXMLObjects().add(buildRequestedAttribute("LegalPersonIdentifier", "http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", true));
        requestedAttributes.getUnknownXMLObjects().add(buildRequestedAttribute("LegalName", "http://eidas.europa.eu/attributes/legalperson/LegalName", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", true));
        extensions.getUnknownXMLObjects().add(requestedAttributes);

        return extensions;
    }

    private XSAny buildRequestedAttribute(String friendlyName, String name, String nameFormat, boolean isRequired) {
        XSAny requestedAttribute = new XSAnyBuilder().buildObject("http://eidas.europa.eu/saml-extensions", "RequestedAttribute", "eidas");
        requestedAttribute.getUnknownAttributes().put(new QName("FriendlyName"), friendlyName);
        requestedAttribute.getUnknownAttributes().put(new QName("Name"), name);
        requestedAttribute.getUnknownAttributes().put(new QName("NameFormat"), nameFormat);
        requestedAttribute.getUnknownAttributes().put(new QName("isRequired"), isRequired ? "true" : "false");
        return requestedAttribute;
    }

    private RequestedAuthnContext buildRequestedAuthnContext(String loa, AuthnContextComparisonTypeEnumeration comparison) {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(comparison);

        AuthnContextClassRef loaAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);

        loaAuthnContextClassRef.setAuthnContextClassRef(loa);

        requestedAuthnContext.getAuthnContextClassRefs().add(loaAuthnContextClassRef);

        return requestedAuthnContext;
    }

    private NameIDPolicy buildNameIdPolicy(String nameId) {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(nameId);
        return nameIDPolicy;
    }
}
