---
theme: default
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Lecture 11: Cryptography in Mobile Applications
  MAT364 - Cryptography Course
drawings:
  persist: false
transition: slide-left
title: Mobile Crypto
css: unocss
---

<style>
.slidev-layout {
  font-size: 0.94rem;
  max-height: 100vh;
  overflow-y: auto;
}

.slidev-layout h1 { font-size: 2rem; margin-bottom: 1rem; }
.slidev-layout h2 { font-size: 1.5rem; margin-bottom: 0.8rem; }
.slidev-layout h3 { font-size: 1.2rem; margin-bottom: 0.6rem; }
.slidev-layout pre { font-size: 0.75rem; max-height: 18rem; overflow-y: auto; margin: 0.5rem 0; }
.slidev-layout code { font-size: 0.8rem; }
.slidev-layout .grid { gap: 1rem; }
.slidev-layout .grid > div { min-height: 0; }
.slidev-layout ul, .slidev-layout ol { margin: 0.5rem 0; padding-left: 1.2rem; }
.slidev-layout li { margin: 0.2rem 0; line-height: 1.4; }

@media (max-width: 768px) {
  .slidev-layout { font-size: 0.85rem; }
  .slidev-layout h1 { font-size: 1.6rem; }
  .slidev-layout h2 { font-size: 1.3rem; }
  .slidev-layout h3 { font-size: 1.1rem; }
  .slidev-layout pre { font-size: 0.7rem; max-height: 16rem; }
}
</style>

# Cryptography in Mobile Applications
## MAT364 - Cryptography Course

**Instructor:** Adil Akhmetov  
**University:** SDU  
**Week 11**

<div class="pt-6">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page →
  </span>
</div>

---
layout: default
---

# Week 11 Focus

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Motivation
- Mobile devices store sensitive data (tokens, keys, PII)
- Unique threats: device loss, jailbreak/root, app isolation
- Platform APIs (Keychain/Keystore) provide hardware-backed security
- Goal: leverage platform security without reinventing crypto

## Learning Outcomes
1. Use iOS Keychain and Android Keystore for secure key storage
2. Implement biometric authentication (Face ID, Touch ID, fingerprint)
3. Apply certificate pinning to prevent MITM attacks
4. Understand app attestation and integrity checks

</div>

<div>

## Agenda
- Mobile security model and threat landscape
- Secure storage: Keychain (iOS) and Keystore (Android)
- Biometric authentication integration
- Certificate pinning strategies
- App attestation (App Attest, Play Integrity)
- Secure network communication in mobile apps
- Lab: Build a secure mobile credential manager

</div>

</div>

---
layout: section
---

# Mobile Security Model

---
layout: default
---

# Mobile Threat Landscape

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Unique Challenges
- **Device loss/theft** - Physical access to device
- **Jailbreak/Root** - Bypassed OS security
- **App isolation** - Sandboxing and permissions
- **Untrusted networks** - Public WiFi, cellular interception
- **Side-channel attacks** - Timing, power analysis

## Attack Vectors
- **Malicious apps** - Steal data from other apps
- **Network interception** - MITM on unsecured WiFi
- **Physical extraction** - Forensic tools on unlocked devices
- **Reverse engineering** - Decompile and analyze app logic

</div>

<div>

## Platform Security Features
- **Hardware Security Modules (HSM)** - Secure Enclave, TrustZone
- **Keychain/Keystore** - Hardware-backed key storage
- **App Sandboxing** - Isolated execution environment
- **Code signing** - Verify app integrity
- **Runtime protection** - ASLR, stack canaries

## Defense Strategy
- Store keys in hardware-backed storage
- Use biometric authentication
- Implement certificate pinning
- Validate app integrity at runtime
- Encrypt sensitive data at rest

</div>

</div>

---
layout: section
---

# iOS Keychain Services

---
layout: default
---

# iOS Keychain Overview

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Key Features
- **Hardware-backed** - Uses Secure Enclave when available
- **App isolation** - Keys accessible only to your app (or app group)
- **Access control** - Require biometric, passcode, or both
- **Keychain sharing** - Share keys across apps in same team
- **iCloud Keychain** - Sync across devices (optional)

## Key Types
- **Generic passwords** - Tokens, API keys
- **Cryptographic keys** - RSA, ECC keys
- **Certificates** - X.509 certificates
- **Identities** - Certificate + private key pair

</div>

<div>

## Swift Example
```swift
import Security

class KeychainManager {
    let service = "com.sdu.mat364.app"
    
    func storeKey(_ key: Data, label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing item
        SecItemDelete(query as CFDictionary)
        
        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.storeFailed(status)
        }
    }
    
    func retrieveKey(label: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            }
            throw KeychainError.retrieveFailed(status)
        }
        
        return result as? Data
    }
}
```

</div>

</div>

---
layout: default
---

# iOS Cryptographic Keys

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Secure Enclave Keys
- **Hardware-backed** - Never leave Secure Enclave
- **Biometric protection** - Require Face ID/Touch ID
- **Operations** - Sign/encrypt without key extraction
- **Use cases** - User authentication, transaction signing

## Key Generation
```swift
import Security

func generateSecureKey() throws -> SecKey {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.sdu.mat364.privatekey".data(using: .utf8)!,
            kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryAny],
                nil
            )!
        ]
    ]
    
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw KeychainError.keyGenerationFailed(error?.takeRetainedValue())
    }
    
    return privateKey
}
```

</div>

<div>

## Signing with Secure Enclave
```swift
func signData(_ data: Data, with key: SecKey) throws -> Data {
    guard SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else {
        throw CryptoError.algorithmNotSupported
    }
    
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        key,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        &error
    ) as Data? else {
        throw CryptoError.signingFailed(error?.takeRetainedValue())
    }
    
    return signature
}

func verifySignature(_ signature: Data, for data: Data, publicKey: SecKey) -> Bool {
    guard SecKeyIsAlgorithmSupported(publicKey, .verify, .ecdsaSignatureMessageX962SHA256) else {
        return false
    }
    
    var error: Unmanaged<CFError>?
    let result = SecKeyVerifySignature(
        publicKey,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        signature as CFData,
        &error
    )
    
    return result
}
```

## Best Practices
- Use Secure Enclave for sensitive keys
- Require biometric authentication for key access
- Store keys with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Never extract private keys from Secure Enclave

</div>

</div>

---
layout: section
---

# Android Keystore System

---
layout: default
---

# Android Keystore Overview

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Key Features
- **Hardware-backed** - Uses Trusted Execution Environment (TEE) or StrongBox
- **Key isolation** - Keys never exposed to app process
- **Authentication required** - Biometric, PIN, pattern
- **Key attestation** - Verify key origin and properties
- **Key import** - Import existing keys securely

## Key Properties
- **Purpose** - Encryption, signing, key agreement
- **Block modes** - GCM, CBC, CTR
- **Padding** - PKCS7, OAEP
- **Digest** - SHA-256, SHA-512
- **Key size** - 128, 192, 256 bits (AES)

</div>

<div>

## Kotlin Example
```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Cipher
import javax.crypto.SecretKey

class AndroidKeystoreManager {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    
    fun generateKey(alias: String, requireAuth: Boolean = true) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(requireAuth)
            .setUserAuthenticationValidityDurationSeconds(60)
            .build()
        
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }
    
    fun getKey(alias: String): SecretKey? {
        return keyStore.getKey(alias, null) as? SecretKey
    }
    
    fun encrypt(data: ByteArray, alias: String): Pair<ByteArray, ByteArray> {
        val key = getKey(alias) ?: throw IllegalStateException("Key not found")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        
        val iv = cipher.iv
        val encrypted = cipher.doFinal(data)
        
        return Pair(encrypted, iv)
    }
}
```

</div>

</div>

---
layout: default
---

# Android Key Attestation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Purpose
- **Verify key origin** - Confirm key was generated in hardware
- **Check key properties** - Validate security features
- **Detect compromised devices** - Identify root/jailbreak
- **Compliance** - Meet security requirements

## Attestation Flow
1. Generate key with attestation
2. Get attestation certificate chain
3. Verify chain against Google/device root
4. Extract key properties from certificate
5. Validate security features

</div>

<div>

## Implementation
```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyAttestationException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

fun generateKeyWithAttestation(alias: String) {
    val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_SIGN
    )
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAttestationChallenge("challenge".toByteArray())
        .build()
    
    val keyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
    )
    keyPairGenerator.initialize(keyGenParameterSpec)
    keyPairGenerator.generateKeyPair()
}

fun verifyAttestation(alias: String): Boolean {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    
    val certChain = keyStore.getCertificateChain(alias)
    if (certChain.isEmpty()) return false
    
    // Verify certificate chain
    val certFactory = CertificateFactory.getInstance("X.509")
    val attestationCert = certChain[0] as X509Certificate
    
    // Check key properties in certificate extensions
    val securityLevel = attestationCert.getExtensionValue(
        "1.3.6.1.4.1.11129.2.1.17"
    )
    
    // Parse and validate security level
    return securityLevel != null && isHardwareBacked(securityLevel)
}
```

</div>

</div>

---
layout: section
---

# Biometric Authentication

---
layout: default
---

# Biometric Integration

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## iOS LocalAuthentication
- **Face ID** - Face recognition (iPhone X+)
- **Touch ID** - Fingerprint (older devices)
- **Passcode fallback** - When biometrics unavailable
- **LAContext** - Manage authentication sessions

## Swift Implementation
```swift
import LocalAuthentication

class BiometricAuth {
    func authenticate(reason: String, completion: @escaping (Bool, Error?) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            completion(false, error)
            return
        }
        
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        ) { success, error in
            DispatchQueue.main.async {
                completion(success, error)
            }
        }
    }
    
    func authenticateForKeyAccess(reason: String, completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        context.localizedFallbackTitle = "Use Passcode"
        
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            nil
        )!
        
        context.setCredential(accessControl, type: .applicationPassword)
        
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        ) { success, _ in
            completion(success)
        }
    }
}
```

</div>

<div>

## Android BiometricPrompt
- **Fingerprint** - Standard biometric
- **Face unlock** - Face recognition
- **Iris** - Iris scanning (Samsung)
- **Fallback** - PIN, pattern, password

## Kotlin Implementation
```kotlin
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

class BiometricAuth(private val activity: FragmentActivity) {
    private val executor = ContextCompat.getMainExecutor(activity)
    
    fun authenticate(callback: (Boolean) -> Unit) {
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    callback(true)
                }
                
                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
                    callback(false)
                }
            }
        )
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Use your fingerprint to authenticate")
            .setNegativeButtonText("Cancel")
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
    
    fun authenticateWithCrypto(cryptoObject: BiometricPrompt.CryptoObject, callback: (Boolean) -> Unit) {
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    // Use cryptoObject.cipher for encryption/decryption
                    callback(true)
                }
                
                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
                    callback(false)
                }
            }
        )
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate to access key")
            .setNegativeButtonText("Cancel")
            .build()
        
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
```

</div>

</div>

---
layout: section
---

# Certificate Pinning

---
layout: default
---

# Certificate Pinning Strategies

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Why Pin?
- **Prevent MITM** - Block proxy tools (Burp, Charles)
- **Trust specific CAs** - Reduce attack surface
- **Detect compromise** - Identify rogue certificates
- **Compliance** - Meet security requirements

## Pinning Methods
- **Public key pinning** - Pin public key hash
- **Certificate pinning** - Pin full certificate
- **SPKI pinning** - Pin Subject Public Key Info
- **Hash pinning** - Pin SHA-256 hash

## Trade-offs
- **Flexibility** - Harder to update certificates
- **Maintenance** - Need backup pins
- **User experience** - App breaks if pin invalid

</div>

<div>

## iOS Certificate Pinning
```swift
import Foundation
import Security

class CertificatePinner: NSObject, URLSessionDelegate {
    let pinnedCertificates: [Data]
    
    init(certificatePaths: [String]) {
        self.pinnedCertificates = certificatePaths.compactMap { path in
            guard let certData = NSData(contentsOfFile: path) as Data? else {
                return nil
            }
            return certData
        }
    }
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Evaluate server trust
        var secresult = SecTrustResultType.invalid
        let status = SecTrustEvaluate(serverTrust, &secresult)
        
        guard status == errSecSuccess else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get server certificates
        let serverCertificates = (0..<SecTrustGetCertificateCount(serverTrust))
            .compactMap { SecTrustGetCertificateAtIndex(serverTrust, $0) }
            .compactMap { SecCertificateCopyData($0) as Data? }
        
        // Check if any server certificate matches pinned certificates
        let isValid = serverCertificates.contains { serverCert in
            pinnedCertificates.contains { pinnedCert in
                serverCert == pinnedCert
            }
        }
        
        completionHandler(
            isValid ? .useCredential : .cancelAuthenticationChallenge,
            isValid ? URLCredential(trust: serverTrust) : nil
        )
    }
}
```

</div>

</div>

---
layout: default
---

# Android Certificate Pinning

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Network Security Config
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.sdu.edu.kz</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

## Application Manifest
```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
</application>
```

</div>

<div>

## Programmatic Pinning (OkHttp)
```kotlin
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

class SecureHttpClient {
    fun createClient(): OkHttpClient {
        val certificatePinner = CertificatePinner.Builder()
            .add("api.sdu.edu.kz", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.sdu.edu.kz", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build()
        
        return OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .build()
    }
    
    fun extractPinHash(certificatePath: String): String {
        val certificate = File(certificatePath).readBytes()
        val x509Cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certificate)) as X509Certificate
        
        val publicKey = x509Cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
        
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }
}
```

## Best Practices
- Use multiple pins (primary + backup)
- Set expiration dates
- Test pin updates before deployment
- Monitor pin failures in production

</div>

</div>

---
layout: section
---

# App Attestation

---
layout: default
---

# iOS App Attestation

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## App Attest API
- **Verify app integrity** - Confirm app not tampered
- **Device integrity** - Detect jailbreak
- **Runtime checks** - Validate at runtime
- **Server validation** - Verify attestation on backend

## Flow
1. Generate key in Secure Enclave
2. Request attestation from Apple
3. Send attestation to server
4. Server validates with Apple
5. Grant access if valid

</div>

<div>

## Swift Implementation
```swift
import CryptoKit
import DeviceCheck

class AppAttestation {
    func generateKey() throws -> Data {
        let keyId = UUID().uuidString
        
        let challenge = Data("challenge".utf8)
        
        DCAppAttestService.shared.generateKey { keyId, error in
            if let error = error {
                print("Key generation failed: \(error)")
                return
            }
            
            guard let keyId = keyId else { return }
            
            // Store keyId for later use
            UserDefaults.standard.set(keyId, forKey: "attestationKeyId")
            
            // Request attestation
            self.requestAttestation(keyId: keyId, challenge: challenge)
        }
    }
    
    func requestAttestation(keyId: String, challenge: Data) {
        DCAppAttestService.shared.attestKey(keyId, clientDataHash: challenge) { attestation, error in
            if let error = error {
                print("Attestation failed: \(error)")
                return
            }
            
            guard let attestation = attestation else { return }
            
            // Send attestation to server for validation
            self.sendAttestationToServer(attestation)
        }
    }
    
    func sendAttestationToServer(_ attestation: Data) {
        // POST to your backend
        // Server validates with Apple's App Attest API
    }
}
```

</div>

</div>

---
layout: default
---

# Android Play Integrity API

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Play Integrity Features
- **Device integrity** - Verify device is genuine
- **App integrity** - Confirm app not tampered
- **Account integrity** - Check Google Play account
- **Server validation** - Verify tokens on backend

## Integrity Signals
- **MEETS_STRONG_INTEGRITY** - Device passes all checks
- **MEETS_BASIC_INTEGRITY** - Device passes basic checks
- **MEETS_DEVICE_INTEGRITY** - Device integrity only

</div>

<div>

## Kotlin Implementation
```kotlin
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.IntegrityTokenResponse

class PlayIntegrity(private val integrityManager: IntegrityManager) {
    suspend fun requestIntegrityToken(nonce: String): String? {
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .setCloudProjectNumber(123456789L) // Your project number
            .build()
        
        return try {
            val response = integrityManager.requestIntegrityToken(request)
            response.token
        } catch (e: Exception) {
            null
        }
    }
    
    fun validateIntegrityToken(token: String): Boolean {
        // Send token to your backend
        // Backend validates with Google Play Integrity API
        // Returns true if device meets integrity requirements
        return false // Implement server-side validation
    }
}

// Usage
class MainActivity : AppCompatActivity() {
    private val integrityManager = IntegrityManagerFactory.create(applicationContext)
    private val playIntegrity = PlayIntegrity(integrityManager)
    
    private suspend fun checkIntegrity() {
        val nonce = generateNonce()
        val token = playIntegrity.requestIntegrityToken(nonce)
        
        if (token != null) {
            val isValid = playIntegrity.validateIntegrityToken(token)
            if (!isValid) {
                // Handle compromised device
                finish()
            }
        }
    }
}
```

</div>

</div>

---
layout: section
---

# Secure Network Communication

---
layout: default
---

# Mobile Network Security

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Best Practices
- **Always use HTTPS** - Never send sensitive data over HTTP
- **Certificate pinning** - Prevent MITM attacks
- **TLS 1.3** - Use latest TLS version
- **Strong cipher suites** - AES-256-GCM, ChaCha20-Poly1305
- **Perfect forward secrecy** - ECDHE key exchange

## iOS URLSession
```swift
let configuration = URLSessionConfiguration.default
configuration.tlsMinimumSupportedProtocolVersion = .TLSv13

let session = URLSession(
    configuration: configuration,
    delegate: CertificatePinner(),
    delegateQueue: nil
)

let url = URL(string: "https://api.sdu.edu.kz/endpoint")!
let task = session.dataTask(with: url) { data, response, error in
    // Handle response
}
task.resume()
```

</div>

<div>

## Android Network Security
```kotlin
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import javax.net.ssl.SSLContext

class SecureNetworkClient {
    fun createClient(): OkHttpClient {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, null, null)
        
        val connectionSpec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
            .cipherSuites(
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_AES_128_GCM_SHA256
            )
            .build()
        
        return OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .connectionSpecs(listOf(connectionSpec))
            .build()
    }
}
```

## Additional Security
- **Certificate transparency** - Monitor certificate issuance
- **HSTS** - Enforce HTTPS
- **Public key pinning** - Pin public keys, not certificates
- **Backup pins** - Multiple pins for flexibility

</div>

</div>

---
layout: section
---

# Lab: Secure Credential Manager

---
layout: default
---

# 🎯 Student Lab Assignment

<div class="p-4 bg-gradient-to-r from-slate-50 to-indigo-50 rounded-lg border border-indigo-200">

## Scenario
Build a secure mobile credential manager that stores API keys, passwords, and tokens. The app must protect data even if the device is lost or compromised.

## Tasks
1. **Secure Storage**: Implement key storage using Keychain (iOS) or Keystore (Android)
2. **Biometric Auth**: Require biometric authentication before accessing credentials
3. **Encryption**: Encrypt all stored credentials using hardware-backed keys
4. **Certificate Pinning**: Implement certificate pinning for API communication
5. **Integrity Check**: Add app attestation to detect tampering

### Deliverables
- Working mobile app (iOS or Android)
- Code demonstrating secure key storage
- Certificate pinning implementation
- Short write-up explaining security measures

</div>

---
layout: default
---

# ✅ Solution Outline

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## iOS Solution
1. **Keychain Storage**
   - Store encrypted credentials in Keychain
   - Use Secure Enclave for encryption keys
   - Require biometric authentication

2. **Biometric Integration**
   - Use LocalAuthentication framework
   - Fallback to passcode if needed

3. **Certificate Pinning**
   - Implement URLSessionDelegate
   - Pin server certificates

4. **App Attestation**
   - Use DCAppAttestService
   - Validate on server

</div>

<div>

## Android Solution
1. **Keystore Storage**
   - Generate AES keys in Android Keystore
   - Encrypt credentials before storage
   - Require biometric authentication

2. **Biometric Integration**
   - Use BiometricPrompt API
   - Integrate with Keystore operations

3. **Certificate Pinning**
   - Use Network Security Config
   - Or OkHttp CertificatePinner

4. **Play Integrity**
   - Request integrity tokens
   - Validate on server

</div>

</div>

---
layout: section
---

# Best Practices & Pitfalls

---
layout: default
---

# Security Checklist

- **Key Management**: Store keys in hardware-backed storage (Keychain/Keystore)
- **Biometric Auth**: Require authentication for sensitive operations
- **Certificate Pinning**: Pin certificates to prevent MITM attacks
- **App Integrity**: Verify app hasn't been tampered with
- **Network Security**: Always use HTTPS with strong cipher suites
- **Data Encryption**: Encrypt sensitive data at rest
- **Secure Deletion**: Properly delete keys when no longer needed
- **Error Handling**: Don't leak sensitive information in error messages

<div class="mt-4 p-3 bg-red-50 rounded-lg text-sm">
<strong>Anti-patterns to avoid:</strong> storing keys in UserDefaults/SharedPreferences, using weak encryption, ignoring certificate validation errors, hardcoding secrets in source code, not requiring authentication for key access.
</div>

---
layout: default
---

# Common Vulnerabilities

<div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">

<div>

## Storage Issues
- **Plaintext storage** - Storing sensitive data unencrypted
- **Weak encryption** - Using deprecated algorithms
- **Key in code** - Hardcoding encryption keys
- **Shared preferences** - Storing secrets in user preferences

## Network Issues
- **HTTP instead of HTTPS** - Sending data over unencrypted channel
- **No certificate pinning** - Vulnerable to MITM
- **Weak TLS** - Using old TLS versions
- **Self-signed certs** - Accepting invalid certificates

</div>

<div>

## Authentication Issues
- **No biometric auth** - Relying only on app-level auth
- **Weak passcodes** - Not enforcing strong passwords
- **Session management** - Long-lived sessions without re-auth
- **Token storage** - Storing tokens insecurely

## Platform Issues
- **Jailbreak/root detection** - Not checking device integrity
- **Debug builds** - Shipping debug builds to production
- **Logging** - Logging sensitive information
- **Backup** - Allowing backups of sensitive data

</div>

</div>

---
layout: default
---

# Summary

- Mobile devices require specialized security measures due to unique threat model
- Use hardware-backed storage (Keychain/Keystore) for sensitive keys
- Implement biometric authentication for user-friendly security
- Apply certificate pinning to prevent MITM attacks on untrusted networks
- Verify app integrity using App Attest (iOS) or Play Integrity (Android)
- Always use HTTPS with strong cipher suites and perfect forward secrecy

<div class="mt-4 text-sm text-gray-600">
<p><strong>Next Week:</strong> Cryptography in blockchain applications (Bitcoin, Ethereum, smart contracts).</p>
<p><strong>Assignment:</strong> Complete the secure credential manager lab and submit code + security analysis.</p>
</div>

---
layout: end
---

# Questions?

<div class="pt-6">
  <span class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Thanks for exploring mobile cryptography! 📱🔐
  </span>
</div>

