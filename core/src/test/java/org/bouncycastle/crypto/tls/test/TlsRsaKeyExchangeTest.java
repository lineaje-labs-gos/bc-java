
package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.tls.TlsRsaKeyExchange;
import org.bouncycastle.util.test.SimpleTest;

import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class TlsRsaKeyExchangeTest extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new TlsRsaKeyExchangeTest());
    }

    private SecureRandom secureRandom;
    private RSAKeyParameters privateKey;
    private RSAKeyParameters publicKey;
    private int protocolVersion;

    public TlsRsaKeyExchangeTest()
    {
        setUp();
    }

    public void setUp()
    {
        // Initialize objects
        secureRandom = new SecureRandom();
        KeyPair keyPair = generateRSAKeyPair();
        privateKey = new RSAKeyParameters(
                true,
                ((RSAPrivateKey) keyPair.getPrivate()).getModulus(),
                ((RSAPrivateKey) keyPair.getPrivate()).getPrivateExponent()
        );
        publicKey = new RSAKeyParameters(
                false,
                ((RSAPublicKey) keyPair.getPublic()).getModulus(),
                ((RSAPublicKey) keyPair.getPublic()).getPublicExponent()
        );
        protocolVersion = 0x0303; // TLS 1.2
    }

    public void testDecryptPreMasterSecret()
    {
        byte[] preMasterSecret = new byte[48];
        secureRandom.nextBytes(preMasterSecret);
        preMasterSecret[0] = (byte) 0x03;
        preMasterSecret[1] = (byte) 0x03; // TLS 1.2

        // Encrypt the pre-master secret
        byte[] encryptedPreMasterSecret = encryptPreMasterSecret(preMasterSecret);

        // Decrypt and verify
        byte[] result = TlsRsaKeyExchange.decryptPreMasterSecret(encryptedPreMasterSecret, privateKey, protocolVersion, secureRandom);

        isTrue(Arrays.equals(preMasterSecret, result));
    }

    private byte[] encryptPreMasterSecret(byte[] preMasterSecret)
    {
        try
        {
            PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
            encoding.init(true, new ParametersWithRandom(publicKey, secureRandom));
            return encoding.processBlock(preMasterSecret, 0, preMasterSecret.length);
        } catch (Exception e)
        {
            throw new RuntimeException("Failed to encrypt pre-master secret", e);
        }
    }

    private KeyPair generateRSAKeyPair()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e)
        {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    @Override
    public String getName()
    {
        return "TlsRsaKeyExchangeTest";
    }

    @Override
    public void performTest() throws Exception
    {
        testDecryptPreMasterSecret();
    }
}

