#  Revocation checking on macOS
This app demonstrates X.509 revocation checking on macOS with 3 different certificate chains:

0. CRL- and OCSP-enabled.  The certificate is non-expired and issued by DigiCert.
1. CRL-enabled.  The certificate is non-expired and issued by Microsoft.
2. CRL-enabled.  The certificate is expired and issued by Microsoft.

It appears that revocation status is not checked in certificate chains 1 and 2.

With each certificate chain, the root certificate is set as a trust anchor using [`SecTrustSetAnchorCertificates(...)`](https://developer.apple.com/documentation/security/1396098-sectrustsetanchorcertificates), and the verification date is set to a date within the end certificate's validity period using [`SecTrustSetVerifyDate(...)`](https://developer.apple.com/documentation/security/1397216-sectrustsetverifydate/).

Running this app will print the following output:
```shell
Running scenario 0:  CRL + OCSP.
SecTrustEvaluateWithError(...) succeeded.
TrustExpirationDate=2022-02-15 18:50:49 +0000
TrustResultValue=4
TrustResultDetails=(
        {
    },
        {
    },
        {
    }
)
TrustEvaluationDate=2024-05-14 23:59:59 +0000
TrustRevocationChecked=1

Running scenario 1:  CRL.
SecTrustEvaluateWithError(...) failed.
Optional(Error Domain=NSOSStatusErrorDomain Code=-67635 ""Microsoft Windows","Microsoft Windows Production PCA 2011","Microsoft Root Certificate Authority 2010" certificates do not meet pinning requirements" UserInfo={NSLocalizedDescription="Microsoft Windows","Microsoft Windows Production PCA 2011","Microsoft Root Certificate Authority 2010" certificates do not meet pinning requirements, NSUnderlyingError=0x10113ddd0 {Error Domain=NSOSStatusErrorDomain Code=-67635 "Certificate 0 “Microsoft Windows” has errors: Failed to check revocation;" UserInfo={NSLocalizedDescription=Certificate 0 “Microsoft Windows” has errors: Failed to check revocation;}}})
TrustEvaluationDate=2022-06-08 18:55:35 +0000
TrustResultDetails=(
        {
        RevocationResponseRequired = 0;
        StatusCodes =         (
            "-2147408861"
        );
    },
        {
    },
        {
    }
)
TrustResultValue=5

Running scenario 2:  CRL and expired.
SecTrustEvaluateWithError(...) failed.
Optional(Error Domain=NSOSStatusErrorDomain Code=-67635 ""Microsoft Windows","Microsoft Windows Production PCA 2011","Microsoft Root Certificate Authority 2010" certificates do not meet pinning requirements" UserInfo={NSLocalizedDescription="Microsoft Windows","Microsoft Windows Production PCA 2011","Microsoft Root Certificate Authority 2010" certificates do not meet pinning requirements, NSUnderlyingError=0x10072f650 {Error Domain=NSOSStatusErrorDomain Code=-67635 "Certificate 0 “Microsoft Windows” has errors: Failed to check revocation;" UserInfo={NSLocalizedDescription=Certificate 0 “Microsoft Windows” has errors: Failed to check revocation;}}})
TrustResultValue=5
TrustResultDetails=(
        {
        RevocationResponseRequired = 0;
        StatusCodes =         (
            "-2147408861"
        );
    },
        {
    },
        {
    }
)
TrustEvaluationDate=2021-12-01 21:29:14 +0000

Program ended with exit code: 0
```

Certificate chains 1 and 2 fail verification with [`RevocationResponseRequired` (-2147408861 / 0x80012423)](https://github.com/apple-oss-distributions/Security/blob/154ef3d9d6f57f0374aa5d6c4b412e8653c1eebe/OSX/sec/Security/SecPolicyChecks.list#L93).

The "certificates do not meet pinning requirements" error only _explicitly_ applies to TLS certificates:
* [Requirements for trusted certificates in iOS 13 and macOS 10.15](https://support.apple.com/en-us/HT210176)
* [About upcoming limits on trusted certificates](https://support.apple.com/en-us/HT211025)