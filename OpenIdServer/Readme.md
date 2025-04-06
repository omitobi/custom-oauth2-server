# OIDC POC + External HSM signing and encryption

### Plans

1. Test possible External Signing
2. Test possible External Encryption
3. Make it work as OIDC Server
4. Make it work with custom claims
5. Make External signing and encryption easily used with any HSM/KMS/etc

### SPecs to cover
1. [The OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
2. [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-core-1_0.html#OpenID.Discovery) [OpenID.Discovery]
3. [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-core-1_0.html#OpenID.Registration) [OpenID.Registration]

OpenID Connect implements authentication as an extension to the OAuth 2.0 authorization process. Use of this extension is requested by Clients by including the openid scope value in the Authorization Request. Information about the authentication performed is returned in a JSON Web Token (JWT) [JWT] called an ID Token (see Section 2). OAuth 2.0 Authentication Servers implementing OpenID Connect are also referred to as OpenID Providers (OPs). OAuth 2.0 Clients using OpenID Connect are also referred to as Relying Parties (RPs).

This specification assumes that the Relying Party has already obtained configuration information about the OpenID Provider, including its Authorization Endpoint and Token Endpoint locations. This information is normally obtained via Discovery, as described in [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-core-1_0.html#OpenID.Discovery) [OpenID.Discovery], or may be obtained via other mechanisms.

Likewise, this specification assumes that the Relying Party has already obtained sufficient credentials and provided information needed to use the OpenID Provider. This is normally done via Dynamic Registration, as described in [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-core-1_0.html#OpenID.Registration) [OpenID.Registration], or may be obtained via other mechanisms. 
