//
//  main.swift
//  x509-revocation-check
//
//  Created by Damon Tivel on 2/7/22.
//

import Security
import SecurityFoundation

let repro = Repro();

repro.Run(scenario: 0, description: "CRL + OCSP");
repro.Run(scenario: 1, description: "CRL");
repro.Run(scenario: 2, description: "CRL and expired");

public final class Repro {
    public func Run(scenario: Int32, description: String) {
        print("Running scenario \(scenario):  \(description).");
        
        let rootCertificate: SecCertificate = loadCertificate(fileName: "root\(scenario)");
        let intermediateCertificate: SecCertificate = loadCertificate(fileName: "intermediate\(scenario)");
        let endCertificate: SecCertificate = loadCertificate(fileName: "end\(scenario)");
        let verifyDate: Date = getVerifyDate(certificate: endCertificate);
        
        let basicPolicy: SecPolicy = SecPolicyCreateBasicX509();
        let revocationPolicy: SecPolicy? = SecPolicyCreateRevocation(
            kSecRevocationUseAnyAvailableMethod | kSecRevocationRequirePositiveResponse
        );
        let policies: Array<SecPolicy> = [basicPolicy, revocationPolicy!];
        let certificates: Array<SecCertificate> = [endCertificate, intermediateCertificate, rootCertificate];
        let anchorCertificates: Array<SecCertificate> = [rootCertificate];
        var trust: SecTrust?;

        var status: OSStatus = SecTrustCreateWithCertificates(
            certificates as CFArray,
            policies as CFArray,
            &trust);
        
        if status != errSecSuccess {
            printErrorDetails(functionName: "SecTrustEvaluate", status: status);
            return;
        }
        
        status = SecTrustSetAnchorCertificates(trust!, anchorCertificates as CFArray);
        
        if status != errSecSuccess {
            printErrorDetails(functionName: "SecTrustSetAnchorCertificates", status: status);
            return;
        }
        
        status = SecTrustSetNetworkFetchAllowed(trust!, true);
        
        if status != errSecSuccess {
            printErrorDetails(functionName: "SecTrustSetNetworkFetchAllowed", status: status);
            return;
        }
        
        status = SecTrustSetVerifyDate(trust!, verifyDate as CFDate);
        
        if status != errSecSuccess {
            printErrorDetails(functionName: "SecTrustSetVerifyDate", status: status);
            return;
        }
        
        var error: CFError?;
        
        let result: Bool = SecTrustEvaluateWithError(trust!, &error);
        
        print("SecTrustEvaluateWithError(...) \(result ? "succeeded" : "failed").");
        
        if !result {
            print(error.debugDescription);
        }
        
        let trustResults = SecTrustCopyResult(trust!) as! [String: Any];
        
        for trustResult in trustResults {
            print("\(trustResult.key)=\(trustResult.value)");
        }
        
        print("");
    }
    
    private func getVerifyDate(certificate: SecCertificate) -> Date {
        let keys = [kSecOIDX509V1ValidityNotAfter] as CFArray;
        let certificateValues: Dictionary = SecCertificateCopyValues(certificate, keys, nil) as! [String: Any];
        let notAfterValues = certificateValues[kSecOIDX509V1ValidityNotAfter as String] as! [String: Any];
        let notAfterRaw = notAfterValues[kSecPropertyKeyValue as String] as! TimeInterval;
        let notAfterDate = Date(timeIntervalSinceReferenceDate: notAfterRaw);
        let verifyDate: Date = Calendar.current.date(byAdding: .day, value: -1, to: notAfterDate)!;

        return verifyDate;
    }
    
    private func loadCertificate(fileName: String) -> SecCertificate {
        let url: URL? = Bundle.main.url(forResource: fileName, withExtension: "cer");
        let data: Data? = try? Data(contentsOf: url!);
        let certificate: SecCertificate? = SecCertificateCreateWithData(kCFAllocatorDefault, data! as CFData);
        
        return certificate!;
    }
    
    private func printErrorDetails(functionName: String, status: OSStatus) {
        print("\(functionName)(...) failed with \(status).");
    
        if let message = SecCopyErrorMessageString(status, nil) {
            print(message);
        }
    }
}
