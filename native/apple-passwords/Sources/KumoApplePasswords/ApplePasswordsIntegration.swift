import AppKit
import AuthenticationServices
import Foundation

/// Only public, supported capabilities. A passkey authorization is not password-vault access.
public struct ApplePasswordsCapabilities: Codable, Sendable {
    public let arbitraryWebsitePasswordFillAvailable: Bool
    public let arbitraryWebsitePasswordFillReason: String
    public let passkeyBrowserAPIAvailable: Bool
    public let passkeyDeviceConfigured: Bool?
    public let passkeyAuthorization: BrowserPasskeyAuthorization
    public let passwordsApplicationInstalled: Bool
}

public enum BrowserPasskeyAuthorization: String, Codable, Sendable {
    case unavailable
    case authorized
    case denied
    case notDetermined
    case unknown
}

public enum ApplePasswordsIntegrationError: LocalizedError {
    case browserPasskeyAPIUnavailable
    case passwordsApplicationNotInstalled

    public var errorDescription: String? {
        switch self {
        case .browserPasskeyAPIUnavailable:
            return "Browser passkey APIs require macOS 13.3 or later."
        case .passwordsApplicationNotInstalled:
            return "The Apple Passwords application is not installed on this Mac."
        }
    }
}

/// Call from the signed browser process on the main actor, never from a renderer or agent.
/// Permission belongs to that app identity; authorizing a standalone probe does not authorize Kumo.
@MainActor
public final class ApplePasswordsIntegration {
    public init() {}

    /// Inspects capability and permission state without requesting authorization or reading credentials.
    public func capabilities() -> ApplePasswordsCapabilities {
        var authorization: BrowserPasskeyAuthorization = .unavailable
        var passkeyAPIAvailable = false
        var deviceConfigured: Bool?
        if #available(macOS 13.3, *) {
            passkeyAPIAvailable = true
            let manager = ASAuthorizationWebBrowserPublicKeyCredentialManager()
            authorization = Self.authorization(manager.authorizationStateForPlatformCredentials)
        }
        if #available(macOS 26.2, *) {
            deviceConfigured = ASAuthorizationWebBrowserPublicKeyCredentialManager.isDeviceConfiguredForPasskeys
        }
        return ApplePasswordsCapabilities(
            arbitraryWebsitePasswordFillAvailable: false,
            arbitraryWebsitePasswordFillReason:
                "No public macOS API verified for this Chromium integration grants arbitrary website password retrieval. Associated-domain password APIs and browser passkey APIs do not provide that capability.",
            passkeyBrowserAPIAvailable: passkeyAPIAvailable,
            passkeyDeviceConfigured: deviceConfigured,
            passkeyAuthorization: authorization,
            passwordsApplicationInstalled: passwordsApplicationURL != nil
        )
    }

    /// Invoke only from a browser-owned control after a user gesture. macOS presents consent.
    /// The browser needs Apple's approved com.apple.developer.web-browser.public-key-credential
    /// managed capability and valid signing/provisioning for arbitrary relying parties.
    public func requestBrowserPasskeyAuthorization() async throws -> BrowserPasskeyAuthorization {
        guard #available(macOS 13.3, *) else {
            throw ApplePasswordsIntegrationError.browserPasskeyAPIUnavailable
        }
        let manager = ASAuthorizationWebBrowserPublicKeyCredentialManager()
        let current = manager.authorizationStateForPlatformCredentials
        guard current == .notDetermined else {
            return Self.authorization(current)
        }
        return await withCheckedContinuation { continuation in
            manager.requestAuthorizationForPublicKeyCredentials { state in
                continuation.resume(returning: Self.authorization(state))
            }
        }
    }

    /// Opens Apple's app normally. The OS controls its unlock policy. This does not fill a webpage,
    /// access the clipboard, read a vault, or suppress Apple authentication prompts.
    public func openPasswordsApplication() async throws {
        guard let applicationURL = passwordsApplicationURL else {
            throw ApplePasswordsIntegrationError.passwordsApplicationNotInstalled
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        _ = try await NSWorkspace.shared.openApplication(at: applicationURL, configuration: configuration)
    }

    private var passwordsApplicationURL: URL? {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Passwords")
    }

    @available(macOS 13.3, *)
    nonisolated private static func authorization(
        _ state: ASAuthorizationWebBrowserPublicKeyCredentialManager.AuthorizationState
    ) -> BrowserPasskeyAuthorization {
        switch state {
        case .authorized: return .authorized
        case .denied: return .denied
        case .notDetermined: return .notDetermined
        @unknown default: return .unknown
        }
    }
}
