# FIDO2 `hmac-secret` for slot kind 3 (OPEN-4)

Research spike, 2026-10-13. Status: **recommendation, waiting on one decision (a domain).** No code yet.

Spec §6.2 defines slot kind 3: the slot secret `S` is the 32-byte `hmac-secret` output of a security key for `salt32`. The params hold `salt32` and the credential ID. Kind 3 slots are **synced**. That is the point of them: one security key unlocks the vault on every device, the way the password does. Everything below follows from that.

## What each platform offers a native app

| Platform | Route to `hmac-secret` | Constraints |
|---|---|---|
| **Windows** | `webauthn.dll` (`webauthn.h`). Since Windows 10 1903, apps without admin rights can't open FIDO HID devices directly; they must go through this API. `WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS` carries PRF inputs (`pHmacSecretSaltValues`). A flag passes raw `hmac-secret` salts instead of PRF inputs. Check the API version at runtime with `WebAuthNGetApiVersionNumber`. | PRF and `hmac-secret` need a recent Windows. Windows 10 has known PRF problems (Bitwarden documents them). Windows Hello's own authenticator historically lacked `hmac-secret`, so this is for external keys. |
| **Linux** | Direct CTAP2 over USB HID: `libfido2` (C, with Rust bindings) or a Rust crate (`ctap-hid-fido2`, `ctap-fido2`). | HID access needs a udev rule (most distributions ship one for FIDO keys). Linux doesn't check the RP ID. |
| **macOS** | Direct CTAP2 over HID (as on Linux) works for unsigned builds. The platform route is AuthenticationServices, whose security-key provider has had PRF in recent releases. | The AuthenticationServices route needs an Associated Domains entitlement for the RP ID. Direct HID may need the HID input permission prompt. |
| **Android** | Credential Manager (Jetpack `androidx.credentials`) with PRF. Security keys are reached over NFC or USB through Google Play Services. | Support is patchy. PRF is reliable for Google Password Manager passkeys, but PRF results from *security keys* through Credential Manager are reported inconsistently: some third-party providers drop the PRF input, and Yubico's enabler doesn't document forwarding it. Needs testing on real keys. The RP ID must be a domain associated with the app through Digital Asset Links. |

## Decisions

1. **RP ID: a domain the project controls** (for example `strata.example` once one exists), not a made-up string.
   - Android and Apple tie a native app's RP IDs to web domains it's verifiably associated with: `/.well-known/assetlinks.json` and `apple-app-site-association`. Windows and direct CTAP don't check, but a kind 3 slot is synced, so its credential has to be usable everywhere, and the strictest platform decides.
   - **This needs a domain and two static files on it.** That is the one thing to decide before implementing.
2. **The salt goes through the PRF transform on every route.** Platform APIs speak WebAuthn PRF, which hashes its input before it reaches the key: `salt = SHA-256("WebAuthn PRF" || 0x00 || input)`. Direct CTAP passes the salt as is. For one credential to give the same `S` everywhere, the spec should fix `input = salt32`. Direct-CTAP code then applies the PRF hash itself, and the Windows call uses PRF inputs, not the raw-salt flag.
3. **User verification: required.** CTAP 2.1 keeps two separate `hmac-secret` secrets per credential, one with UV and one without, so the choice must never vary. With UV, a stolen key alone opens nothing, and the key's own PIN retry counter rate-limits guesses. This fits the policy: a synced protector must be Strong.
4. **Discoverable (resident) credential: not required.** The slot stores the credential ID (§6.2 params), so the key needs no resident slot. Keys have few of those, and non-discoverable credentials keep working on old keys. Request `hmac-secret`/PRF **at creation**: some keys refuse PRF later otherwise.
5. **Two touches at enrollment.** `hmac-secret` isn't returned at creation by most keys. `hmac-secret-mc` does return it, but only on firmware from 2024 on. Enrollment does create, then a get-assertion to read `S`, and uses `-mc` when the key offers it.

## Proposed implementation (after the domain)

- **Rust, desktop.** A `Fido2` protector-like module, though kind 3 is a synced slot, not a `PlatformProtector`. Windows goes through `webauthn.dll` via the `windows` crate (`Win32_Networking_WindowsWebServices`). Linux and macOS use direct CTAP2. Only enrollment and unlock talk to the key; the core already has the kind 3 slot format.
- **Android.** Credential Manager with PRF, behind the same interface. Ship it as "experimental" until it's verified on at least one NFC key and one USB key.
- **Tests.** Fixed vectors for the PRF salt transform; a software authenticator (`soft-fido2`, or a mock) in CI; a manual checklist with a real YubiKey.

## Spec changes this implies

- §6.2 kind 3: RP ID = the project domain; UV required; `S` = PRF output for input `salt32`, i.e. `hmac-secret` over `SHA-256("WebAuthn PRF" || 0x00 || salt32)`.
- OPEN-4 then resolves, apart from the domain itself.

## Sources

- [Microsoft: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_authenticator_get_assertion_options)
- [microsoft/webauthn core API overview (DeepWiki)](https://deepwiki.com/microsoft/webauthn/2-core-webauthn-api)
- [go-ctap/winhello: Windows WebAuthn API bindings with hmac-secret/PRF](https://github.com/go-ctap/winhello)
- [Chromium: Intent to Ship WebAuthn PRF](https://groups.google.com/a/chromium.org/g/blink-dev/c/iTNOgLwD2bI)
- [Yubico: PRF extension](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/)
- [Yubico: security key PRF support](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Pseudo-Random_Function_PRF_Support.html)
- [Corbado: Passkeys and WebAuthn PRF for end-to-end encryption (2026)](https://www.corbado.com/blog/passkeys-prf-webauthn)
- [Android: Credential Manager release notes](https://developer.android.com/jetpack/androidx/releases/credentials)
- [Unstoppable Wallet issue on PRF-capable security keys via Credential Manager](https://github.com/horizontalsystems/unstoppable-wallet-android/issues/9483)
- [Authnkey PR: Android prfAlreadyHashed for hybrid PRF](https://github.com/mimi89999/Authnkey/pull/95)
- [Bitwarden: log in with passkeys (PRF requirements, Windows 10 issues)](https://bitwarden.com/help/login-with-passkeys)
- [KeePassXC discussion: FIDO2 hmac-secret](https://github.com/keepassxreboot/keepassxc/discussions/9506)
- [ctap-fido2 crate (hmac-secret over HID)](https://docs.rs/ctap-fido2)
- [libfido2](https://github.com/nevun/libfido2)
