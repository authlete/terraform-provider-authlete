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
	HasClientNames() bool
	GetDescription() string
	GetDescriptionOk() (*string, bool)
	HasDescription() bool
	SetDescription(v string)
	HasDescriptions() bool
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
	HasClientType() bool
	HasApplicationType() bool
	SetApplicationTypeNil()
	UnsetApplicationType()
	GetLogoUri() string
	GetLogoUriOk() (*string, bool)
	HasLogoUri() bool
	SetLogoUri(v string)
	HasLogoUris() bool
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
	HasGrantTypes() bool
	HasResponseTypes() bool
	GetRedirectUris() []string
	GetRedirectUrisOk() ([]string, bool)
	HasRedirectUris() bool
	SetRedirectUris(v []string)
	HasAuthorizationSignAlg() bool
	HasAuthorizationEncryptionAlg() bool
	HasAuthorizationEncryptionEnc() bool
	HasTokenAuthMethod() bool
	HasTokenAuthSignAlg() bool
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
	HasRequestSignAlg() bool
	HasRequestEncryptionAlg() bool
	HasRequestEncryptionEnc() bool
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
	HasIdTokenSignAlg() bool
	HasIdTokenEncryptionAlg() bool
	HasIdTokenEncryptionEnc() bool
	GetAuthTimeRequired() bool
	GetAuthTimeRequiredOk() (*bool, bool)
	HasAuthTimeRequired() bool
	SetAuthTimeRequired(v bool)
	HasSubjectType() bool
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
	HasUserInfoSignAlg() bool
	HasUserInfoEncryptionAlg() bool
	HasUserInfoEncryptionEnc() bool
	GetLoginUri() string
	GetLoginUriOk() (*string, bool)
	HasLoginUri() bool
	SetLoginUri(v string)
	GetTosUri() string
	GetTosUriOk() (*string, bool)
	HasTosUri() bool
	SetTosUri(v string)
	HasTosUris() bool
	GetPolicyUri() string
	GetPolicyUriOk() (*string, bool)
	HasPolicyUri() bool
	SetPolicyUri(v string)
	HasPolicyUris() bool
	GetClientUri() string
	GetClientUriOk() (*string, bool)
	HasClientUri() bool
	SetClientUri(v string)
	HasClientUris() bool
	GetBcDeliveryMode() string
	GetBcDeliveryModeOk() (*string, bool)
	HasBcDeliveryMode() bool
	SetBcDeliveryMode(v string)
	GetBcNotificationEndpoint() string
	GetBcNotificationEndpointOk() (*string, bool)
	HasBcNotificationEndpoint() bool
	SetBcNotificationEndpoint(v string)
	HasBcRequestSignAlg() bool
	GetBcUserCodeRequired() bool
	GetBcUserCodeRequiredOk() (*bool, bool)
	HasBcUserCodeRequired() bool
	SetBcUserCodeRequired(v bool)
	HasAttributes() bool
	HasExtension() bool
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
	HasClientRegistrationTypes() bool
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
