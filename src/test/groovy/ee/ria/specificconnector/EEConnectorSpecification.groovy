package ee.ria.specificconnector

import io.restassured.RestAssured
import io.restassured.filter.log.RequestLoggingFilter
import io.restassured.filter.log.ResponseLoggingFilter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.opensaml.core.config.InitializationService
import org.opensaml.security.credential.Credential
import spock.lang.Shared
import spock.lang.Specification

import java.nio.file.Paths
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate

class EEConnectorSpecification extends Specification {
    @Shared
    Properties props = new Properties()
    @Shared
    Credential signatureCredential
    @Shared
    Credential encryptionCredential
    @Shared
    X509Certificate encryptionCertificate
    @Shared
    X509Certificate spSigningCertificate
    @Shared
    Credential metadataCredential
    @Shared
    Credential expiredCredential
    @Shared
    Credential unsupportedCredential
    @Shared
    Credential unsupportedByConfigurationCredential
    @Shared
    X509Certificate spMetadataSigningCertificate
    @Shared
    String defaultContentSecurityPolicy = "block-all-mixed-content; default-src 'self'; object-src: 'none'; frame-ancestors 'none'; script-src 'self' 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='"
    static String REQUEST_TYPE_POST = "post"
    static String REQUEST_TYPE_GET = "get"
    static String REQUESTER_ID = "TEST-REQUESTER-ID"
    static String IDP_USERNAME = "xavi"
    static String IDP_PASSWORD = "creus"
    static String LOA_HIGH = "http://eidas.europa.eu/LoA/high"
    static String LOA_NON_NOTIFIED = "http://non.eidas.eu/NotNotified/LoA/1"

    def setupSpec() {
        InitializationService.initialize()
        Security.addProvider(new BouncyCastleProvider())


        URL envFile = this.getClass().getResource('/.env')
        Properties envProperties = new Properties()
        if (envFile) {
            envFile.withInputStream {
                envProperties.load(it)
            }
            Paths.get(envProperties.getProperty("configuration_base_path"), envProperties.getProperty("configuration_path"), "application.properties").withInputStream {
                props.load(it)
            }

            if (envProperties."log_all" && envProperties."log_all" != "false") {
                RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
            }
        } else {
            this.getClass().getResource('/application.properties').withInputStream {
                props.load(it)
            }
        }

        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("ee-spservice.keystore.file")).withInputStream {
                    keystore.load(it, props.get("ee-spservice.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."ee-spservice.keystore.file"}").withInputStream {
                    keystore.load(it, props.get("ee-spservice.keystore.password").toString().toCharArray())
                }
            }

            signatureCredential = KeystoreUtils.getCredential(keystore, props."ee-spservice.keystore.requestSigningKeyId" as String, props."ee-spservice.keystore.requestSigningKeyPassword" as String)
            spSigningCertificate = (X509Certificate) keystore.getCertificate(props."ee-spservice.keystore.requestSigningKeyId".toString())
        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }


        try {
            KeyStore encryptionKeystore = KeyStore.getInstance("PKCS12")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("ee-spservice.keystore.file")).withInputStream {
                    encryptionKeystore.load(it, props.get("ee-spservice.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."ee-spservice.keystore.file"}").withInputStream {
                    encryptionKeystore.load(it, props.get("ee-spservice.keystore.password").toString().toCharArray())
                }
            }
            encryptionCredential = KeystoreUtils.getCredential(encryptionKeystore, props."ee-spservice.keystore.samlAssertionDecryptKey" as String, props."ee-spservice.keystore.samlAssertionDecryptPassword" as String)
            encryptionCertificate = (X509Certificate) encryptionKeystore.getCertificate(props."ee-spservice.keystore.samlAssertionDecryptKey".toString())
        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }

        try {
            KeyStore metadataKeystore = KeyStore.getInstance("PKCS12")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("ee-spservice.keystore.file")).withInputStream {
                    metadataKeystore.load(it, props.get("ee-spservice.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."ee-spservice.keystore.file"}").withInputStream {
                    metadataKeystore.load(it, props.get("ee-spservice.keystore.password").toString().toCharArray())
                }
            }
            metadataCredential = KeystoreUtils.getCredential(metadataKeystore, props."ee-spservice.keystore.metadataKeyId" as String, props."ee-spservice.keystore.metadataKeyPassword" as String)
        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }

        try {
            KeyStore expiredKeystore = KeyStore.getInstance("PKCS12")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("ee-spservice.test.keystore.file")).withInputStream {
                    expiredKeystore.load(it, props.get("ee-spservice.test.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."ee-spservice.test.keystore.file"}").withInputStream {
                    expiredKeystore.load(it, props.get("ee-spservice.test.keystore.password").toString().toCharArray())
                }
            }
            expiredCredential = KeystoreUtils.getCredential(expiredKeystore, props."ee-spservice.test.keystore.expiredKeyId" as String, props."ee-spservice.test.keystore.expiredKeyPassword" as String)
        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }

        try {
            KeyStore unsupportedKeystore = KeyStore.getInstance("PKCS12")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("ee-spservice.test.keystore.file")).withInputStream {
                    unsupportedKeystore.load(it, props.get("ee-spservice.test.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."ee-spservice.test.keystore.file"}").withInputStream {
                    unsupportedKeystore.load(it, props.get("ee-spservice.test.keystore.password").toString().toCharArray())
                }
            }
            unsupportedCredential = KeystoreUtils.getCredential(unsupportedKeystore, props."ee-spservice.test.keystore.unsupportedKeyId" as String, props."ee-spservice.test.keystore.unsupportedKeyPassword" as String)
        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }

        try {
            KeyStore unsupportedByConfigurationKeystore = KeyStore.getInstance("PKCS12")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("ee-spservice.test.keystore.file")).withInputStream {
                    unsupportedByConfigurationKeystore.load(it, props.get("ee-spservice.test.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."ee-spservice.test.keystore.file"}").withInputStream {
                    unsupportedByConfigurationKeystore.load(it, props.get("ee-spservice.test.keystore.password").toString().toCharArray())
                }
            }
            unsupportedByConfigurationCredential = KeystoreUtils.getCredential(unsupportedByConfigurationKeystore, props."ee-spservice.test.keystore.unsupportedByConfigurationKeyId" as String, props."ee-spservice.test.keystore.unsupportedByConfigurationKeyPassword" as String)
        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }

        try {
            KeyStore spResponseSigningKeystore = KeyStore.getInstance("PKCS12")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("ee-connector.truststore.file")).withInputStream {
                    spResponseSigningKeystore.load(it, props.get("ee-connector.truststore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."ee-connector.truststore.file"}").withInputStream {
                    spResponseSigningKeystore.load(it, props.get("ee-connector.truststore.password").toString().toCharArray())
                }
            }
            spMetadataSigningCertificate = (X509Certificate) spResponseSigningKeystore.getCertificate(props."ee-connector.truststore.spRequestSigningKeyId".toString())
        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }
    }
}