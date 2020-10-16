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

class SpecificConnectorSpecification extends Specification {
    @Shared
    Properties props = new Properties()
    @Shared
    Credential signatureCredential
    @Shared
    Credential encryptionCredential

    def setupSpec() {
        InitializationService.initialize()
        Security.addProvider(new BouncyCastleProvider())


        URL envFile = this.getClass().getResource('/.env')
        Properties envProperties = new Properties()
        if (envFile) {
            envFile.withInputStream {
                envProperties.load(it)
                //envProperties."configuration_base_path"
                //envProperties."configuration_path"
            }
            Paths.get(envProperties.getProperty("configuration_base_path"), envProperties.getProperty("configuration_path"), "application.properties").withInputStream {
                props.load(it)
            }

            //Log all requests and responses for debugging
            if (envProperties."log_all" && envProperties."log_all" != "false") {
                RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter())
            }
        } else {
            this.getClass().getResource('/application.properties').withInputStream {
                props.load(it)
            }
        }
        /*
        try {
            KeyStore keystore = KeyStore.getInstance("jks")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("connector.keystore.file")).withInputStream {
                    keystore.load(it, props.get("connector.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."connector.keystore.file"}").withInputStream {
                    keystore.load(it, props.get("connector.keystore.password").toString().toCharArray())
                }
            }

            signatureCredential = KeystoreUtils.getCredential(keystore, props."connector.keystore.requestSigningKeyId" as String, props."connector.keystore.requestSigningKeyPassword" as String)
        }

        /*
        config = new RestAssuredConfig().sslConfig(new SSLConfig().
                    keyStore(testTaraProperties.getFrontEndKeystore(), testTaraProperties.getFrontEndKeystorePassword()).
                    trustStore(testTaraProperties.getBackEndTruststore(), testTaraProperties.getBackEndTruststorePassword()))
         */
        /*
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }
        */
        /*
        try {
            KeyStore encryptionKeystore = KeyStore.getInstance("jks")
            if (envFile) {
                Paths.get(envProperties.getProperty("configuration_base_path"), props.getProperty("connector.encryption.keystore.file")).withInputStream {
                    encryptionKeystore.load(it, props.get("connector.encryption.keystore.password").toString().toCharArray())
                }
            } else {
                this.getClass().getResource("/${props."connector.encryption.keystore.file"}").withInputStream {
                    encryptionKeystore.load(it, props.get("connector.encryption.keystore.password").toString().toCharArray())
                }
            }
            encryptionCredential = KeystoreUtils.getCredential(encryptionKeystore, props."connector.encryption.keystore.requestEncryptionKeyId" as String, props."connector.encryption.keystore.requestEncryptionKeyPassword" as String)

        }
        catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e)
        }
        */
    }
}