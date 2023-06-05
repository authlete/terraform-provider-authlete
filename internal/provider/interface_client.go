package provider

type myClient interface {
	GetNumber() int32
	GetNumberOk() (*int32, bool)
	HasNumber() bool
	SetNumber(v int32)
	GetServiceNumber() int32
	GetServiceNumberOk() (*int32, bool)
	HasServiceNumber() bool
	SetServiceNumber(v int32)
	GetDeveloper() string
	GetDeveloperOk() (*string, bool)
	HasDeveloper() bool
	SetDeveloper(v string)
	GetClientName() string
	GetClientNameOk() (*string, bool)
	HasClientName() bool
	SetClientName(v string)
	// GetClientNames() []TaggedValue
	// GetClientNamesOk() ([]TaggedValue, bool)
	HasClientNames() bool
	// SetClientNames(v []TaggedValue)
	GetDescription() string
	GetDescriptionOk() (*string, bool)
	HasDescription() bool
	SetDescription(v string)
	// GetDescriptions() []TaggedValue
	// GetDescriptionsOk() ([]TaggedValue, bool)
	HasDescriptions() bool
	// SetDescriptions(v []TaggedValue)
	GetClientId() int64
	GetClientIdOk() (*int64, bool)
	HasClientId() bool
	SetClientId(v int64)
	GetClientSecret() string
	GetClientSecretOk() (*string, bool)
	HasClientSecret() bool
	SetClientSecret(v string)
	GetClientIdAlias() string
	GetClientIdAliasOk() (*string, bool)
	HasClientIdAlias() bool
	SetClientIdAlias(v string)
	GetClientIdAliasEnabled() bool
	GetClientIdAliasEnabledOk() (*bool, bool)
	HasClientIdAliasEnabled() bool
	SetClientIdAliasEnabled(v bool)
	// GetClientType() ClientType
	// GetClientTypeOk() (*ClientType, bool)
	HasClientType() bool
	// SetClientType(v ClientType)
	// GetApplicationType() ApplicationType
	// GetApplicationTypeOk() (*ApplicationType, bool)
	HasApplicationType() bool
	// SetApplicationType(v ApplicationType)
	SetApplicationTypeNil()
	UnsetApplicationType()
	GetLogoUri() string
	GetLogoUriOk() (*string, bool)
	HasLogoUri() bool
	SetLogoUri(v string)
	// GetLogoUris() []TaggedValue
	// GetLogoUrisOk() ([]TaggedValue, bool)
	HasLogoUris() bool
	// SetLogoUris(v []TaggedValue)
	GetContacts() []string
	GetContactsOk() ([]string, bool)
	HasContacts() bool
	SetContacts(v []string)
	GetTlsClientCertificateBoundAccessTokens() bool
	GetTlsClientCertificateBoundAccessTokensOk() (*bool, bool)
	HasTlsClientCertificateBoundAccessTokens() bool
	SetTlsClientCertificateBoundAccessTokens(v bool)
	GetDynamicallyRegistered() bool
	GetDynamicallyRegisteredOk() (*bool, bool)
	HasDynamicallyRegistered() bool
	SetDynamicallyRegistered(v bool)
	GetSoftwareId() string
	GetSoftwareIdOk() (*string, bool)
	HasSoftwareId() bool
	SetSoftwareId(v string)
	GetSoftwareVersion() string
	GetSoftwareVersionOk() (*string, bool)
	HasSoftwareVersion() bool
	SetSoftwareVersion(v string)
	GetRegistrationAccessTokenHash() string
	GetRegistrationAccessTokenHashOk() (*string, bool)
	HasRegistrationAccessTokenHash() bool
	SetRegistrationAccessTokenHash(v string)
	GetCreatedAt() int64
	GetCreatedAtOk() (*int64, bool)
	HasCreatedAt() bool
	SetCreatedAt(v int64)
	GetModifiedAt() int64
	GetModifiedAtOk() (*int64, bool)
	HasModifiedAt() bool
	SetModifiedAt(v int64)
	// GetGrantTypes() []GrantType
	// GetGrantTypesOk() ([]GrantType, bool)
	HasGrantTypes() bool
	// SetGrantTypes(v []GrantType)
	// GetResponseTypes() []ResponseType
	// GetResponseTypesOk() ([]ResponseType, bool)
	HasResponseTypes() bool
	// SetResponseTypes(v []ResponseType)
	GetRedirectUris() []string
	GetRedirectUrisOk() ([]string, bool)
	HasRedirectUris() bool
	SetRedirectUris(v []string)
	// GetAuthorizationSignAlg() JwsAlg
	// GetAuthorizationSignAlgOk() (*JwsAlg, bool)
	HasAuthorizationSignAlg() bool
	// SetAuthorizationSignAlg(v JwsAlg)
	// GetAuthorizationEncryptionAlg() JweAlg
	// GetAuthorizationEncryptionAlgOk() (*JweAlg, bool)
	HasAuthorizationEncryptionAlg() bool
	// SetAuthorizationEncryptionAlg(v JweAlg)
	// GetAuthorizationEncryptionEnc() JweEnc
	// GetAuthorizationEncryptionEncOk() (*JweEnc, bool)
	HasAuthorizationEncryptionEnc() bool
	// SetAuthorizationEncryptionEnc(v JweEnc)
	// GetTokenAuthMethod() ClientAuthenticationMethod
	// GetTokenAuthMethodOk() (*ClientAuthenticationMethod, bool)
	HasTokenAuthMethod() bool
	// SetTokenAuthMethod(v ClientAuthenticationMethod)
	// GetTokenAuthSignAlg() JwsAlg
	// GetTokenAuthSignAlgOk() (*JwsAlg, bool)
	HasTokenAuthSignAlg() bool
	// SetTokenAuthSignAlg(v JwsAlg)
	GetSelfSignedCertificateKeyId() string
	GetSelfSignedCertificateKeyIdOk() (*string, bool)
	HasSelfSignedCertificateKeyId() bool
	SetSelfSignedCertificateKeyId(v string)
	GetTlsClientAuthSubjectDn() string
	GetTlsClientAuthSubjectDnOk() (*string, bool)
	HasTlsClientAuthSubjectDn() bool
	SetTlsClientAuthSubjectDn(v string)
	GetTlsClientAuthSanDns() string
	GetTlsClientAuthSanDnsOk() (*string, bool)
	HasTlsClientAuthSanDns() bool
	SetTlsClientAuthSanDns(v string)
	GetTlsClientAuthSanUri() string
	GetTlsClientAuthSanUriOk() (*string, bool)
	HasTlsClientAuthSanUri() bool
	SetTlsClientAuthSanUri(v string)
	GetTlsClientAuthSanIp() string
	GetTlsClientAuthSanIpOk() (*string, bool)
	HasTlsClientAuthSanIp() bool
	SetTlsClientAuthSanIp(v string)
	GetTlsClientAuthSanEmail() string
	GetTlsClientAuthSanEmailOk() (*string, bool)
	HasTlsClientAuthSanEmail() bool
	SetTlsClientAuthSanEmail(v string)
	GetParRequired() bool
	GetParRequiredOk() (*bool, bool)
	HasParRequired() bool
	SetParRequired(v bool)
	GetRequestObjectRequired() bool
	GetRequestObjectRequiredOk() (*bool, bool)
	HasRequestObjectRequired() bool
	SetRequestObjectRequired(v bool)
	// GetRequestSignAlg() JwsAlg
	// GetRequestSignAlgOk() (*JwsAlg, bool)
	HasRequestSignAlg() bool
	// SetRequestSignAlg(v JwsAlg)
	// GetRequestEncryptionAlg() JweAlg
	// GetRequestEncryptionAlgOk() (*JweAlg, bool)
	HasRequestEncryptionAlg() bool
	// SetRequestEncryptionAlg(v JweAlg)
	// GetRequestEncryptionEnc() JweEnc
	// GetRequestEncryptionEncOk() (*JweEnc, bool)
	HasRequestEncryptionEnc() bool
	// SetRequestEncryptionEnc(v JweEnc)
	GetRequestUris() []string
	GetRequestUrisOk() ([]string, bool)
	HasRequestUris() bool
	SetRequestUris(v []string)
	GetDefaultMaxAge() int32
	GetDefaultMaxAgeOk() (*int32, bool)
	HasDefaultMaxAge() bool
	SetDefaultMaxAge(v int32)
	GetDefaultAcrs() []string
	GetDefaultAcrsOk() ([]string, bool)
	HasDefaultAcrs() bool
	SetDefaultAcrs(v []string)
	// GetIdTokenSignAlg() JwsAlg
	// GetIdTokenSignAlgOk() (*JwsAlg, bool)
	HasIdTokenSignAlg() bool
	// SetIdTokenSignAlg(v JwsAlg)
	// GetIdTokenEncryptionAlg() JweAlg
	// GetIdTokenEncryptionAlgOk() (*JweAlg, bool)
	HasIdTokenEncryptionAlg() bool
	// SetIdTokenEncryptionAlg(v JweAlg)
	// GetIdTokenEncryptionEnc() JweEnc
	// GetIdTokenEncryptionEncOk() (*JweEnc, bool)
	HasIdTokenEncryptionEnc() bool
	// SetIdTokenEncryptionEnc(v JweEnc)
	GetAuthTimeRequired() bool
	GetAuthTimeRequiredOk() (*bool, bool)
	HasAuthTimeRequired() bool
	SetAuthTimeRequired(v bool)
	// GetSubjectType() SubjectType
	// GetSubjectTypeOk() (*SubjectType, bool)
	HasSubjectType() bool
	// SetSubjectType(v SubjectType)
	GetSectorIdentifierUri() string
	GetSectorIdentifierUriOk() (*string, bool)
	HasSectorIdentifierUri() bool
	SetSectorIdentifierUri(v string)
	GetDerivedSectorIdentifier() string
	GetDerivedSectorIdentifierOk() (*string, bool)
	HasDerivedSectorIdentifier() bool
	SetDerivedSectorIdentifier(v string)
	GetJwksUri() string
	GetJwksUriOk() (*string, bool)
	HasJwksUri() bool
	SetJwksUri(v string)
	GetJwks() string
	GetJwksOk() (*string, bool)
	HasJwks() bool
	SetJwks(v string)
	// GetUserInfoSignAlg() JwsAlg
	// GetUserInfoSignAlgOk() (*JwsAlg, bool)
	HasUserInfoSignAlg() bool
	// SetUserInfoSignAlg(v JwsAlg)
	// GetUserInfoEncryptionAlg() JweAlg
	// GetUserInfoEncryptionAlgOk() (*JweAlg, bool)
	HasUserInfoEncryptionAlg() bool
	// SetUserInfoEncryptionAlg(v JweAlg)
	// GetUserInfoEncryptionEnc() JweEnc
	// GetUserInfoEncryptionEncOk() (*JweEnc, bool)
	HasUserInfoEncryptionEnc() bool
	// SetUserInfoEncryptionEnc(v JweEnc)
	GetLoginUri() string
	GetLoginUriOk() (*string, bool)
	HasLoginUri() bool
	SetLoginUri(v string)
	GetTosUri() string
	GetTosUriOk() (*string, bool)
	HasTosUri() bool
	SetTosUri(v string)
	// GetTosUris() []TaggedValue
	// GetTosUrisOk() ([]TaggedValue, bool)
	HasTosUris() bool
	// SetTosUris(v []TaggedValue)
	GetPolicyUri() string
	GetPolicyUriOk() (*string, bool)
	HasPolicyUri() bool
	SetPolicyUri(v string)
	// GetPolicyUris() []TaggedValue
	// GetPolicyUrisOk() ([]TaggedValue, bool)
	HasPolicyUris() bool
	// SetPolicyUris(v []TaggedValue)
	GetClientUri() string
	GetClientUriOk() (*string, bool)
	HasClientUri() bool
	SetClientUri(v string)
	// GetClientUris() []TaggedValue
	// GetClientUrisOk() ([]TaggedValue, bool)
	HasClientUris() bool
	// SetClientUris(v []TaggedValue)
	GetBcDeliveryMode() string
	GetBcDeliveryModeOk() (*string, bool)
	HasBcDeliveryMode() bool
	SetBcDeliveryMode(v string)
	GetBcNotificationEndpoint() string
	GetBcNotificationEndpointOk() (*string, bool)
	HasBcNotificationEndpoint() bool
	SetBcNotificationEndpoint(v string)
	// GetBcRequestSignAlg() JwsAlg
	// GetBcRequestSignAlgOk() (*JwsAlg, bool)
	HasBcRequestSignAlg() bool
	// SetBcRequestSignAlg(v JwsAlg)
	GetBcUserCodeRequired() bool
	GetBcUserCodeRequiredOk() (*bool, bool)
	HasBcUserCodeRequired() bool
	SetBcUserCodeRequired(v bool)
	// GetAttributes() []Pair
	// GetAttributesOk() ([]Pair, bool)
	HasAttributes() bool
	// SetAttributes(v []interface{})
	// GetExtension() ClientExtension
	// GetExtensionOk() (*ClientExtension, bool)
	HasExtension() bool
	// SetExtension(v
	GetAuthorizationDetailsTypes() []string
	GetAuthorizationDetailsTypesOk() ([]string, bool)
	HasAuthorizationDetailsTypes() bool
	SetAuthorizationDetailsTypes(v []string)
	GetCustomMetadata() string
	GetCustomMetadataOk() (*string, bool)
	HasCustomMetadata() bool
	SetCustomMetadata(v string)
	GetFrontChannelRequestObjectEncryptionRequired() bool
	GetFrontChannelRequestObjectEncryptionRequiredOk() (*bool, bool)
	HasFrontChannelRequestObjectEncryptionRequired() bool
	SetFrontChannelRequestObjectEncryptionRequired(v bool)
	GetRequestObjectEncryptionAlgMatchRequired() bool
	GetRequestObjectEncryptionAlgMatchRequiredOk() (*bool, bool)
	HasRequestObjectEncryptionAlgMatchRequired() bool
	SetRequestObjectEncryptionAlgMatchRequired(v bool)
	GetRequestObjectEncryptionEncMatchRequired() bool
	GetRequestObjectEncryptionEncMatchRequiredOk() (*bool, bool)
	HasRequestObjectEncryptionEncMatchRequired() bool
	SetRequestObjectEncryptionEncMatchRequired(v bool)
	GetDigestAlgorithm() string
	GetDigestAlgorithmOk() (*string, bool)
	HasDigestAlgorithm() bool
	SetDigestAlgorithm(v string)
	GetSingleAccessTokenPerSubject() bool
	GetSingleAccessTokenPerSubjectOk() (*bool, bool)
	HasSingleAccessTokenPerSubject() bool
	SetSingleAccessTokenPerSubject(v bool)
	GetPkceRequired() bool
	GetPkceRequiredOk() (*bool, bool)
	HasPkceRequired() bool
	SetPkceRequired(v bool)
	GetPkceS256Required() bool
	GetPkceS256RequiredOk() (*bool, bool)
	HasPkceS256Required() bool
	SetPkceS256Required(v bool)
	GetDpopRequired() bool
	GetDpopRequiredOk() (*bool, bool)
	HasDpopRequired() bool
	SetDpopRequired(v bool)
	GetAutomaticallyRegistered() bool
	GetAutomaticallyRegisteredOk() (*bool, bool)
	HasAutomaticallyRegistered() bool
	SetAutomaticallyRegistered(v bool)
	GetExplicitlyRegistered() bool
	GetExplicitlyRegisteredOk() (*bool, bool)
	HasExplicitlyRegistered() bool
	SetExplicitlyRegistered(v bool)
	GetRsResponseSigned() bool
	GetRsResponseSignedOk() (*bool, bool)
	HasRsResponseSigned() bool
	SetRsResponseSigned(v bool)
	GetRsSignedRequestKeyId() string
	GetRsSignedRequestKeyIdOk() (*string, bool)
	HasRsSignedRequestKeyId() bool
	SetRsSignedRequestKeyId(v string)
	// GetClientRegistrationTypes() []ClientRegistrationType
	// GetClientRegistrationTypesOk() ([]ClientRegistrationType, bool)
	HasClientRegistrationTypes() bool
	// SetClientRegistrationTypes(v []ClientRegistrationType)
	GetOrganizationName() string
	GetOrganizationNameOk() (*string, bool)
	HasOrganizationName() bool
	SetOrganizationName(v string)
	GetSignedJwksUri() string
	GetSignedJwksUriOk() (*string, bool)
	HasSignedJwksUri() bool
	SetSignedJwksUri(v string)
	GetEntityId() string
	GetEntityIdOk() (*string, bool)
	HasEntityId() bool
	SetEntityId(v string)
	GetTrustAnchorId() string
	GetTrustAnchorIdOk() (*string, bool)
	HasTrustAnchorId() bool
	SetTrustAnchorId(v string)
	GetTrustChain() []string
	GetTrustChainOk() ([]string, bool)
	HasTrustChain() bool
	SetTrustChain(v []string)
	GetTrustChainExpiresAt() int64
	GetTrustChainExpiresAtOk() (*int64, bool)
	HasTrustChainExpiresAt() bool
	SetTrustChainExpiresAt(v int64)
	GetTrustChainUpdatedAt() int64
	GetTrustChainUpdatedAtOk() (*int64, bool)
	HasTrustChainUpdatedAt() bool
	SetTrustChainUpdatedAt(v int64)
	MarshalJSON() ([]byte, error)
	ToMap() (map[string]interface{}, error)
}

// type myClientExtension interface {
// 	GetRequestableScopes() []string
// 	GetRequestableScopesOk() ([]string, bool)
// 	HasRequestableScopes() bool
// 	SetRequestableScopes(v []string)
// 	GetRequestableScopesEnabled() bool
// 	GetRequestableScopesEnabledOk() (*bool, bool)
// 	HasRequestableScopesEnabled() bool
// 	SetRequestableScopesEnabled(v bool)
// 	GetAccessTokenDuration() int64
// 	GetAccessTokenDurationOk() (*int64, bool)
// 	HasAccessTokenDuration() bool
// 	SetAccessTokenDuration(v int64)
// 	GetRefreshTokenDuration() int64
// 	GetRefreshTokenDurationOk() (*int64, bool)
// 	HasRefreshTokenDuration() bool
// 	SetRefreshTokenDuration(v int64)
// 	GetTokenExchangePermitted() bool
// 	GetTokenExchangePermittedOk() (*bool, bool)
// 	HasTokenExchangePermitted() bool
// 	SetTokenExchangePermitted(v bool)
// }
