package dev.samstevens.totp;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.NtpTimeProvider;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public class TotpTest {
    public static void main(String[] args) throws Exception {

        SecretGenerator secretGenerator = new DefaultSecretGenerator(64);
        //String secret = secretGenerator.generate();
        String secret = "4ECL72PO6YYV7RUVS2ZCMLWISEJ5VZ4C";
        System.out.println("Secret is: "+secret);

        //CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1,6);
        TimeProvider timeProvider = new SystemTimeProvider();
        //TimeProvider timeProvider = new NtpTimeProvider("pool.ntp.org",5000);
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        // sets the time period for codes to be valid for to 60 seconds
        verifier.setAllowedTimePeriodDiscrepancy(3);
        long currentBucket = Math.floorDiv(timeProvider.getTime(), 30);
        //verifier.setTimePeriod(1);
        String code = codeGenerator.generate(secret,currentBucket);
        // secret = the shared secret for the user
        // code = the code submitted by the user
        boolean successful = verifier.isValidCode(secret,code);

        System.out.println("Secret Key is: "+secret+ " Code is: "+code );
        System.out.println("Verification Results: "+successful);
    }
}
