package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.tls.TlsRsaKeyExchange;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class CustomPKCS1EncodingTest extends SimpleTest
{
    static final int HEADER_LENGTH = 10;
    SecureRandom secureRandom = new SecureRandom();
    KeyPair keyPair = generateRSAKeyPair();
    RSAKeyParameters privateKey = new RSAKeyParameters(
                true,
                        ((RSAPrivateKey) keyPair.getPrivate()).getModulus(),
                ((RSAPrivateKey) keyPair.getPrivate()).getPrivateExponent()
        );
    RSAKeyParameters publicKey = new RSAKeyParameters(
                false,
                        ((RSAPublicKey) keyPair.getPublic()).getModulus(),
                ((RSAPublicKey) keyPair.getPublic()).getPublicExponent()
        );
    RSABlindedEngine cipher = new RSABlindedEngine();
    CustomPKCS1Encoding encode = new CustomPKCS1Encoding(cipher);
    byte[] preMasterSecret = new byte[48];
    int protocolVersion; // TLS 1.2

    public static void main(String[] args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new CustomPKCS1EncodingTest());
    }
    public void testCustomPKCS1Encoding() throws Exception
    {
        secureRandom.nextBytes(preMasterSecret);
        preMasterSecret[0] = (byte) 0x03;
        preMasterSecret[1] = (byte) 0x03; // TLS 1.2
        protocolVersion = 0x0303; // TLS 1.2
        encode.init(true, new ParametersWithRandom(publicKey, secureRandom));
        byte[] encryptedPreMasterSecret = encode.processBlock(preMasterSecret, 0, preMasterSecret.length);
        byte[] result = TlsRsaKeyExchange.decryptPreMasterSecret(encryptedPreMasterSecret, privateKey, protocolVersion, secureRandom);

        isTrue(Arrays.equals(result, preMasterSecret));

        isEquals(encode.getUnderlyingCipher(), cipher);

        isEquals(encode.getInputBlockSize(), cipher.getInputBlockSize() - HEADER_LENGTH);

        isEquals(encode.getOutputBlockSize(), cipher.getOutputBlockSize());
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
        return "CustomPKCS1EncodingTest";
    }

    @Override
    public void performTest() throws Exception
    {
        testCustomPKCS1Encoding();
    }
}