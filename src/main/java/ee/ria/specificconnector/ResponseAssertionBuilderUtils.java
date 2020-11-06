package ee.ria.specificconnector;

import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;

public class ResponseAssertionBuilderUtils extends ResponseBuilderBase {

    protected EncryptedAssertion buildEncrAssertionWithMinLegal(Credential signCredential, Credential encCredential, String inResponseId, String recipient, DateTime issueInstant, Integer acceptableTimeMin, String loa, String givenName, String familyName, String personIdentifier, String dateOfBirth, String legalName, String legalPno, String issuerValue, String audienceUri) throws SecurityException, SignatureException, MarshallingException, EncryptionException {
        Signature signature = prepareSignature(signCredential);
        Assertion assertion = buildLegalAssertionForSigning(inResponseId, recipient ,issueInstant, acceptableTimeMin, loa, givenName, familyName, personIdentifier, dateOfBirth, legalName, legalPno, issuerValue, audienceUri);
        assertion.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(signature);

        return encryptAssertion(assertion, encCredential);
    }

    protected Assertion buildAssertionForSigning(String inResponseId, String recipient, DateTime issueInstant, Integer acceptableTimeMin, String loa, String givenName, String familyName, String personIdentifier, String dateOfBirth, String issuerValue, String audienceUri) {
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setIssueInstant(issueInstant);
        assertion.setID(OpenSAMLUtils.generateSecureRandomId());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(buildIssuer(issuerValue));
        assertion.setSubject(buildSubject(inResponseId, recipient, issueInstant, acceptableTimeMin, personIdentifier));
        assertion.setConditions(buildConditions(audienceUri, issueInstant, acceptableTimeMin));
        assertion.getAuthnStatements().add(buildAuthnStatement(issueInstant,loa));
        assertion.getAttributeStatements().add(buildMinimalAttributeStatement(givenName, familyName, personIdentifier, dateOfBirth));
        return assertion;
    }

    protected Assertion buildLegalAssertionForSigning(String inResponseId, String recipient, DateTime issueInstant, Integer acceptableTimeMin, String loa, String givenName, String familyName, String personIdentifier, String dateOfBirth, String legalName, String legalPno, String issuerValue, String audienceUri) {
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setIssueInstant(issueInstant);
        assertion.setID(OpenSAMLUtils.generateSecureRandomId());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(buildIssuer(issuerValue));
        assertion.setSubject(buildSubject(inResponseId, recipient, issueInstant, acceptableTimeMin, personIdentifier));
        assertion.setConditions(buildConditions(audienceUri, issueInstant, acceptableTimeMin));
        assertion.getAuthnStatements().add(buildAuthnStatement(issueInstant,loa));
        assertion.getAttributeStatements().add(buildMinimalAttributeStatementWithLegalPerson(givenName, familyName, personIdentifier, dateOfBirth, legalName, legalPno));
        return assertion;
    }


    protected Signature prepareSignature(Credential signCredential) throws SecurityException {
        Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(signCredential);
        signature.setSignatureAlgorithm(getSignatureAlgorithm(signCredential));
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfo keyInfo = x509KeyInfoGeneratorFactory.newInstance().generate(signCredential);
        signature.setKeyInfo(keyInfo);
        return signature;
    }

    protected EncryptedAssertion encryptAssertion (Assertion assertion,Credential encCredential) throws EncryptionException {
        KeyEncryptionParameters keyParams = new KeyEncryptionParameters();
        keyParams.setEncryptionCredential(encCredential);
        keyParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
        keyParams.setKeyInfoGenerator(keyInfoGenerator);

        DataEncryptionParameters encryptParams = new DataEncryptionParameters();
        encryptParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        Encrypter samlEncrypter = new Encrypter(encryptParams, keyParams);
        samlEncrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
        EncryptedAssertion encryptedAssertion = samlEncrypter.encrypt(assertion);
        return  encryptedAssertion;
    }

    protected EncryptedAssertion buildEncrAssertionWithoutSubject(Credential signCredential, Credential encCredential, String inResponseId, String recipient, DateTime issueInstant, Integer acceptableTimeMin, String loa, String givenName, String familyName, String personIdentifier, String dateOfBirth, String issuerValue, String audienceUri) throws SecurityException, SignatureException, MarshallingException, EncryptionException {
        Signature signature = prepareSignature(signCredential);
        Assertion assertion = buildAssertionForSigning(inResponseId, recipient ,issueInstant, acceptableTimeMin, loa, givenName, familyName, personIdentifier, dateOfBirth, issuerValue, audienceUri);
        assertion.setSubject(null);
        assertion.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(signature);

        return encryptAssertion(assertion, encCredential);
    }

    protected EncryptedAssertion buildEncrAssertionWithAudienceCnt(Integer audienceCnt, Credential signCredential, Credential encCredential, String inResponseId, String recipient, DateTime issueInstant, Integer acceptableTimeMin, String loa, String givenName, String familyName, String personIdentifier, String dateOfBirth, String issuerValue, String audienceUri) throws SecurityException, SignatureException, MarshallingException, EncryptionException {
        Signature signature = prepareSignature(signCredential);
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setIssueInstant(issueInstant);
        assertion.setID(OpenSAMLUtils.generateSecureRandomId());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(buildIssuer(issuerValue));
        assertion.setSubject(buildSubject(inResponseId, recipient, issueInstant, acceptableTimeMin, personIdentifier));
        assertion.getAuthnStatements().add(buildAuthnStatement(issueInstant, loa));
        if (audienceCnt == 0) {
            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(issueInstant);
            conditions.setNotOnOrAfter(issueInstant.plusMinutes(acceptableTimeMin));
            AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
            conditions.getAudienceRestrictions().add(audienceRestriction);
            assertion.setConditions(conditions);
        }
        else if (audienceCnt == 1) {
            assertion.setConditions(buildConditions(audienceUri, issueInstant, acceptableTimeMin));
        }
        else if (audienceCnt == 2) {
            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(issueInstant);
            conditions.setNotOnOrAfter(issueInstant.plusMinutes(acceptableTimeMin));
            AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
            Audience audience = new AudienceBuilder().buildObject();
            audience.setAudienceURI("someRandomUri");
            Audience audience2 = new AudienceBuilder().buildObject();
            audience2.setAudienceURI(audienceUri);
            audienceRestriction.getAudiences().add(audience2);
            conditions.getAudienceRestrictions().add(audienceRestriction);
            assertion.setConditions(conditions);
        }

        assertion.getAttributeStatements().add(buildMinimalAttributeStatement(givenName, familyName, personIdentifier, dateOfBirth));
        assertion.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(signature);

        return encryptAssertion(assertion, encCredential);
    }

    protected EncryptedAssertion buildEncrAssertionWithSubjectConfirmationCnt(Integer subjectConfirmationCnt, String subjectConfMethod, Credential signCredential, Credential encCredential, String inResponseId, String recipient, DateTime issueInstant, Integer acceptableTimeMin, String loa, String givenName, String familyName, String personIdentifier, String dateOfBirth, String issuerValue, String audienceUri) throws SecurityException, SignatureException, MarshallingException, EncryptionException {
        Signature signature = prepareSignature(signCredential);
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setIssueInstant(issueInstant);
        assertion.setID(OpenSAMLUtils.generateSecureRandomId());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(buildIssuer(issuerValue));
        assertion.getAuthnStatements().add(buildAuthnStatement(issueInstant, loa));
        assertion.setConditions(buildConditions(audienceUri, issueInstant, acceptableTimeMin));

        if (subjectConfirmationCnt == 0) {
            Subject subject = new SubjectBuilder().buildObject();
            NameID nameID = new NameIDBuilder().buildObject();
            nameID.setValue(personIdentifier);
            nameID.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            nameID.setNameQualifier("http://C-PEPS.gov.xx");
            subject.setNameID(nameID);
            assertion.setSubject(subject);
        }
        else if (subjectConfirmationCnt == 1) {
            Subject subject = buildSubject(inResponseId, recipient, issueInstant, acceptableTimeMin, personIdentifier);
            subject.getSubjectConfirmations().get(0).setMethod(subjectConfMethod);
            assertion.setSubject(subject);
        }
        else if (subjectConfirmationCnt == 2) {
            Subject subject = new SubjectBuilder().buildObject();
            NameID nameID = new NameIDBuilder().buildObject();
            nameID.setValue(personIdentifier);
            nameID.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            nameID.setNameQualifier("http://C-PEPS.gov.xx");
            subject.setNameID(nameID);
            SubjectConfirmation subjectConf = new SubjectConfirmationBuilder().buildObject();
            subjectConf.setMethod(subjectConfMethod);
            SubjectConfirmationData subConfData = new SubjectConfirmationDataBuilder().buildObject();
            subConfData.setAddress("172.24.0.1"); //TODO: this needs to be configurable probably
            subConfData.setInResponseTo(inResponseId);
            subConfData.setNotOnOrAfter(issueInstant.plusMinutes(acceptableTimeMin));
            subConfData.setRecipient(recipient);
            subjectConf.setSubjectConfirmationData(subConfData);
            subject.getSubjectConfirmations().add(subjectConf);
            SubjectConfirmation subjectConf2 = new SubjectConfirmationBuilder().buildObject();
            subjectConf2.setMethod(subjectConfMethod);
            subjectConf2.setSubjectConfirmationData(subConfData);
            subject.getSubjectConfirmations().add(subjectConf2);
            assertion.setSubject(subject);
        }

        assertion.getAttributeStatements().add(buildMinimalAttributeStatement(givenName, familyName, personIdentifier, dateOfBirth));
        assertion.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(signature);

        return encryptAssertion(assertion, encCredential);
    }

    protected EncryptedAssertion buildEncrAssertionNameIdCnt(Integer nameIdCnt, String nameIdFormat,Credential signCredential, Credential encCredential, String inResponseId, String recipient, DateTime issueInstant, Integer acceptableTimeMin, String loa, String givenName, String familyName, String personIdentifier, String dateOfBirth, String issuerValue, String audienceUri) throws SecurityException, SignatureException, MarshallingException, EncryptionException {
        Signature signature = prepareSignature(signCredential);
        Assertion assertion = buildAssertionForSigning(inResponseId, recipient ,issueInstant, acceptableTimeMin, loa, givenName, familyName, personIdentifier, dateOfBirth, issuerValue, audienceUri);

        if (nameIdCnt == 0) {
            assertion.getSubject().setNameID(null);
        }
        else if (nameIdCnt == 1) {
            assertion.getSubject().getNameID().setFormat(nameIdFormat);
        }
        else if (nameIdCnt == 2) {
            //TODO: Have to find a way for that
        }

        assertion.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(signature);

        return encryptAssertion(assertion, encCredential);
    }

}
