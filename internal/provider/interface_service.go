package provider

type IService interface {
	GetNumber() int32
	GetNumberOk() (*int32, bool)
	HasNumber() bool
	SetNumber(v int32)
	GetServiceOwnerNumber() int32
	GetServiceOwnerNumberOk() (*int32, bool)
	HasServiceOwnerNumber() bool
	SetServiceOwnerNumber(v int32)
	GetServiceName() string
	GetServiceNameOk() (*string, bool)
	HasServiceName() bool
	SetServiceName(v string)
	GetIssuer() string
	GetIssuerOk() (*string, bool)
	HasIssuer() bool
	SetIssuer(v string)
	GetDescription() string
	GetDescriptionOk() (*string, bool)
	HasDescription() bool
	SetDescription(v string)
	GetApiKey() int64
	GetApiKeyOk() (*int64, bool)
	HasApiKey() bool
	SetApiKey(v int64)
	GetApiSecret() string
	GetApiSecretOk() (*string, bool)
	HasApiSecret() bool
	SetApiSecret(v string)
	GetClientsPerDeveloper() int32
	GetClientsPerDeveloperOk() (*int32, bool)
	HasClientsPerDeveloper() bool
	SetClientsPerDeveloper(v int32)
	GetClientIdAliasEnabled() bool
	GetClientIdAliasEnabledOk() (*bool, bool)
	HasClientIdAliasEnabled() bool
	SetClientIdAliasEnabled(v bool)
	HasMetadata() bool
	GetCreatedAt() int64
	GetCreatedAtOk() (*int64, bool)
	HasCreatedAt() bool
	SetCreatedAt(v int64)
	GetModifiedAt() int64
	GetModifiedAtOk() (*int64, bool)
	HasModifiedAt() bool
	SetModifiedAt(v int64)
	GetAuthenticationCallbackEndpoint() string
	GetAuthenticationCallbackEndpointOk() (*string, bool)
	HasAuthenticationCallbackEndpoint() bool
	SetAuthenticationCallbackEndpoint(v string)
	GetAuthenticationCallbackApiKey() string
	GetAuthenticationCallbackApiKeyOk() (*string, bool)
	HasAuthenticationCallbackApiKey() bool
	SetAuthenticationCallbackApiKey(v string)
	GetAuthenticationCallbackApiSecret() string
	GetAuthenticationCallbackApiSecretOk() (*string, bool)
	HasAuthenticationCallbackApiSecret() bool
	SetAuthenticationCallbackApiSecret(v string)
	HasSupportedSnses() bool
	HasSnsCredentials() bool
	GetSupportedAcrs() []string
	GetSupportedAcrsOk() ([]string, bool)
	HasSupportedAcrs() bool
	SetSupportedAcrs(v []string)
	GetDeveloperAuthenticationCallbackEndpoint() string
	GetDeveloperAuthenticationCallbackEndpointOk() (*string, bool)
	HasDeveloperAuthenticationCallbackEndpoint() bool
	SetDeveloperAuthenticationCallbackEndpoint(v string)
	GetDeveloperAuthenticationCallbackApiKey() string
	GetDeveloperAuthenticationCallbackApiKeyOk() (*string, bool)
	HasDeveloperAuthenticationCallbackApiKey() bool
	SetDeveloperAuthenticationCallbackApiKey(v string)
	GetDeveloperAuthenticationCallbackApiSecret() string
	GetDeveloperAuthenticationCallbackApiSecretOk() (*string, bool)
	HasDeveloperAuthenticationCallbackApiSecret() bool
	SetDeveloperAuthenticationCallbackApiSecret(v string)
	HasSupportedDeveloperSnses() bool
	GetDeveloperSnsCredentials() string
	GetDeveloperSnsCredentialsOk() (*string, bool)
	HasDeveloperSnsCredentials() bool
	SetDeveloperSnsCredentials(v string)
	HasSupportedGrantTypes() bool
	HasSupportedResponseTypes() bool
	GetSupportedAuthorizationDetailsTypes() []string
	GetSupportedAuthorizationDetailsTypesOk() ([]string, bool)
	HasSupportedAuthorizationDetailsTypes() bool
	SetSupportedAuthorizationDetailsTypes(v []string)
	HasSupportedServiceProfiles() bool
	GetErrorDescriptionOmitted() bool
	GetErrorDescriptionOmittedOk() (*bool, bool)
	HasErrorDescriptionOmitted() bool
	SetErrorDescriptionOmitted(v bool)
	GetErrorUriOmitted() bool
	GetErrorUriOmittedOk() (*bool, bool)
	HasErrorUriOmitted() bool
	SetErrorUriOmitted(v bool)
	GetAuthorizationEndpoint() string
	GetAuthorizationEndpointOk() (*string, bool)
	HasAuthorizationEndpoint() bool
	SetAuthorizationEndpoint(v string)
	GetDirectAuthorizationEndpointEnabled() bool
	GetDirectAuthorizationEndpointEnabledOk() (*bool, bool)
	HasDirectAuthorizationEndpointEnabled() bool
	SetDirectAuthorizationEndpointEnabled(v bool)
	GetSupportedUiLocales() []string
	GetSupportedUiLocalesOk() ([]string, bool)
	HasSupportedUiLocales() bool
	SetSupportedUiLocales(v []string)
	HasSupportedDisplays() bool
	GetPkceRequired() bool
	GetPkceRequiredOk() (*bool, bool)
	HasPkceRequired() bool
	SetPkceRequired(v bool)
	GetPkceS256Required() bool
	GetPkceS256RequiredOk() (*bool, bool)
	HasPkceS256Required() bool
	SetPkceS256Required(v bool)
	GetAuthorizationResponseDuration() int64
	GetAuthorizationResponseDurationOk() (*int64, bool)
	HasAuthorizationResponseDuration() bool
	SetAuthorizationResponseDuration(v int64)
	GetTokenEndpoint() string
	GetTokenEndpointOk() (*string, bool)
	HasTokenEndpoint() bool
	SetTokenEndpoint(v string)
	GetDirectTokenEndpointEnabled() bool
	GetDirectTokenEndpointEnabledOk() (*bool, bool)
	HasDirectTokenEndpointEnabled() bool
	SetDirectTokenEndpointEnabled(v bool)
	HasSupportedTokenAuthMethods() bool
	GetMissingClientIdAllowed() bool
	GetMissingClientIdAllowedOk() (*bool, bool)
	HasMissingClientIdAllowed() bool
	SetMissingClientIdAllowed(v bool)
	GetRevocationEndpoint() string
	GetRevocationEndpointOk() (*string, bool)
	HasRevocationEndpoint() bool
	SetRevocationEndpoint(v string)
	GetDirectRevocationEndpointEnabled() bool
	GetDirectRevocationEndpointEnabledOk() (*bool, bool)
	HasDirectRevocationEndpointEnabled() bool
	SetDirectRevocationEndpointEnabled(v bool)
	HasSupportedRevocationAuthMethods() bool
	GetIntrospectionEndpoint() string
	GetIntrospectionEndpointOk() (*string, bool)
	HasIntrospectionEndpoint() bool
	SetIntrospectionEndpoint(v string)
	GetDirectIntrospectionEndpointEnabled() bool
	GetDirectIntrospectionEndpointEnabledOk() (*bool, bool)
	HasDirectIntrospectionEndpointEnabled() bool
	SetDirectIntrospectionEndpointEnabled(v bool)
	HasSupportedIntrospectionAuthMethods() bool
	GetPushedAuthReqEndpoint() string
	GetPushedAuthReqEndpointOk() (*string, bool)
	HasPushedAuthReqEndpoint() bool
	SetPushedAuthReqEndpoint(v string)
	GetPushedAuthReqDuration() int64
	GetPushedAuthReqDurationOk() (*int64, bool)
	HasPushedAuthReqDuration() bool
	SetPushedAuthReqDuration(v int64)
	GetParRequired() bool
	GetParRequiredOk() (*bool, bool)
	HasParRequired() bool
	SetParRequired(v bool)
	GetRequestObjectRequired() bool
	GetRequestObjectRequiredOk() (*bool, bool)
	HasRequestObjectRequired() bool
	SetRequestObjectRequired(v bool)
	GetTraditionalRequestObjectProcessingApplied() bool
	GetTraditionalRequestObjectProcessingAppliedOk() (*bool, bool)
	HasTraditionalRequestObjectProcessingApplied() bool
	SetTraditionalRequestObjectProcessingApplied(v bool)
	GetMutualTlsValidatePkiCertChain() bool
	GetMutualTlsValidatePkiCertChainOk() (*bool, bool)
	HasMutualTlsValidatePkiCertChain() bool
	SetMutualTlsValidatePkiCertChain(v bool)
	GetTrustedRootCertificates() []string
	GetTrustedRootCertificatesOk() ([]string, bool)
	HasTrustedRootCertificates() bool
	SetTrustedRootCertificates(v []string)
	HasMtlsEndpointAliases() bool
	GetAccessTokenType() string
	GetAccessTokenTypeOk() (*string, bool)
	HasAccessTokenType() bool
	SetAccessTokenType(v string)
	GetTlsClientCertificateBoundAccessTokens() bool
	GetTlsClientCertificateBoundAccessTokensOk() (*bool, bool)
	HasTlsClientCertificateBoundAccessTokens() bool
	SetTlsClientCertificateBoundAccessTokens(v bool)
	GetAccessTokenDuration() int64
	GetAccessTokenDurationOk() (*int64, bool)
	HasAccessTokenDuration() bool
	SetAccessTokenDuration(v int64)
	GetSingleAccessTokenPerSubject() bool
	GetSingleAccessTokenPerSubjectOk() (*bool, bool)
	HasSingleAccessTokenPerSubject() bool
	SetSingleAccessTokenPerSubject(v bool)
	HasAccessTokenSignAlg() bool
	GetAccessTokenSignatureKeyId() string
	GetAccessTokenSignatureKeyIdOk() (*string, bool)
	HasAccessTokenSignatureKeyId() bool
	SetAccessTokenSignatureKeyId(v string)
	GetRefreshTokenDuration() int64
	GetRefreshTokenDurationOk() (*int64, bool)
	HasRefreshTokenDuration() bool
	SetRefreshTokenDuration(v int64)
	GetRefreshTokenDurationKept() bool
	GetRefreshTokenDurationKeptOk() (*bool, bool)
	HasRefreshTokenDurationKept() bool
	SetRefreshTokenDurationKept(v bool)
	GetRefreshTokenDurationReset() bool
	GetRefreshTokenDurationResetOk() (*bool, bool)
	HasRefreshTokenDurationReset() bool
	SetRefreshTokenDurationReset(v bool)
	GetRefreshTokenKept() bool
	GetRefreshTokenKeptOk() (*bool, bool)
	HasRefreshTokenKept() bool
	SetRefreshTokenKept(v bool)
	HasSupportedScopes() bool
	GetScopeRequired() bool
	GetScopeRequiredOk() (*bool, bool)
	HasScopeRequired() bool
	SetScopeRequired(v bool)
	GetIdTokenDuration() int64
	GetIdTokenDurationOk() (*int64, bool)
	HasIdTokenDuration() bool
	SetIdTokenDuration(v int64)
	GetAllowableClockSkew() int32
	GetAllowableClockSkewOk() (*int32, bool)
	HasAllowableClockSkew() bool
	SetAllowableClockSkew(v int32)
	HasSupportedClaimTypes() bool
	GetSupportedClaimLocales() []string
	GetSupportedClaimLocalesOk() ([]string, bool)
	HasSupportedClaimLocales() bool
	SetSupportedClaimLocales(v []string)
	GetSupportedClaims() []string
	GetSupportedClaimsOk() ([]string, bool)
	HasSupportedClaims() bool
	SetSupportedClaims(v []string)
	GetClaimShortcutRestrictive() bool
	GetClaimShortcutRestrictiveOk() (*bool, bool)
	HasClaimShortcutRestrictive() bool
	SetClaimShortcutRestrictive(v bool)
	GetJwksUri() string
	GetJwksUriOk() (*string, bool)
	HasJwksUri() bool
	SetJwksUri(v string)
	GetDirectJwksEndpointEnabled() bool
	GetDirectJwksEndpointEnabledOk() (*bool, bool)
	HasDirectJwksEndpointEnabled() bool
	SetDirectJwksEndpointEnabled(v bool)
	GetJwks() string
	GetJwksOk() (*string, bool)
	HasJwks() bool
	SetJwks(v string)
	GetIdTokenSignatureKeyId() string
	GetIdTokenSignatureKeyIdOk() (*string, bool)
	HasIdTokenSignatureKeyId() bool
	SetIdTokenSignatureKeyId(v string)
	GetUserInfoSignatureKeyId() string
	GetUserInfoSignatureKeyIdOk() (*string, bool)
	HasUserInfoSignatureKeyId() bool
	SetUserInfoSignatureKeyId(v string)
	GetAuthorizationSignatureKeyId() string
	GetAuthorizationSignatureKeyIdOk() (*string, bool)
	HasAuthorizationSignatureKeyId() bool
	SetAuthorizationSignatureKeyId(v string)
	GetUserInfoEndpoint() string
	GetUserInfoEndpointOk() (*string, bool)
	HasUserInfoEndpoint() bool
	SetUserInfoEndpoint(v string)
	GetDirectUserInfoEndpointEnabled() bool
	GetDirectUserInfoEndpointEnabledOk() (*bool, bool)
	HasDirectUserInfoEndpointEnabled() bool
	SetDirectUserInfoEndpointEnabled(v bool)
	GetDynamicRegistrationSupported() bool
	GetDynamicRegistrationSupportedOk() (*bool, bool)
	HasDynamicRegistrationSupported() bool
	SetDynamicRegistrationSupported(v bool)
	GetRegistrationEndpoint() string
	GetRegistrationEndpointOk() (*string, bool)
	HasRegistrationEndpoint() bool
	SetRegistrationEndpoint(v string)
	GetRegistrationManagementEndpoint() string
	GetRegistrationManagementEndpointOk() (*string, bool)
	HasRegistrationManagementEndpoint() bool
	SetRegistrationManagementEndpoint(v string)
	GetPolicyUri() string
	GetPolicyUriOk() (*string, bool)
	HasPolicyUri() bool
	SetPolicyUri(v string)
	GetTosUri() string
	GetTosUriOk() (*string, bool)
	HasTosUri() bool
	SetTosUri(v string)
	GetServiceDocumentation() string
	GetServiceDocumentationOk() (*string, bool)
	HasServiceDocumentation() bool
	SetServiceDocumentation(v string)
	GetBackchannelAuthenticationEndpoint() string
	GetBackchannelAuthenticationEndpointOk() (*string, bool)
	HasBackchannelAuthenticationEndpoint() bool
	SetBackchannelAuthenticationEndpoint(v string)
	HasSupportedBackchannelTokenDeliveryModes() bool
	GetBackchannelAuthReqIdDuration() int32
	GetBackchannelAuthReqIdDurationOk() (*int32, bool)
	HasBackchannelAuthReqIdDuration() bool
	SetBackchannelAuthReqIdDuration(v int32)
	GetBackchannelPollingInterval() int32
	GetBackchannelPollingIntervalOk() (*int32, bool)
	HasBackchannelPollingInterval() bool
	SetBackchannelPollingInterval(v int32)
	GetBackchannelUserCodeParameterSupported() bool
	GetBackchannelUserCodeParameterSupportedOk() (*bool, bool)
	HasBackchannelUserCodeParameterSupported() bool
	SetBackchannelUserCodeParameterSupported(v bool)
	GetBackchannelBindingMessageRequiredInFapi() bool
	GetBackchannelBindingMessageRequiredInFapiOk() (*bool, bool)
	HasBackchannelBindingMessageRequiredInFapi() bool
	SetBackchannelBindingMessageRequiredInFapi(v bool)
	GetDeviceAuthorizationEndpoint() string
	GetDeviceAuthorizationEndpointOk() (*string, bool)
	HasDeviceAuthorizationEndpoint() bool
	SetDeviceAuthorizationEndpoint(v string)
	GetDeviceVerificationUri() string
	GetDeviceVerificationUriOk() (*string, bool)
	HasDeviceVerificationUri() bool
	SetDeviceVerificationUri(v string)
	GetDeviceVerificationUriComplete() string
	GetDeviceVerificationUriCompleteOk() (*string, bool)
	HasDeviceVerificationUriComplete() bool
	SetDeviceVerificationUriComplete(v string)
	GetDeviceFlowCodeDuration() int32
	GetDeviceFlowCodeDurationOk() (*int32, bool)
	HasDeviceFlowCodeDuration() bool
	SetDeviceFlowCodeDuration(v int32)
	GetDeviceFlowPollingInterval() int32
	GetDeviceFlowPollingIntervalOk() (*int32, bool)
	HasDeviceFlowPollingInterval() bool
	SetDeviceFlowPollingInterval(v int32)
	HasUserCodeCharset() bool
	GetUserCodeLength() int32
	GetUserCodeLengthOk() (*int32, bool)
	HasUserCodeLength() bool
	SetUserCodeLength(v int32)
	GetSupportedTrustFrameworks() []string
	GetSupportedTrustFrameworksOk() ([]string, bool)
	HasSupportedTrustFrameworks() bool
	SetSupportedTrustFrameworks(v []string)
	GetSupportedEvidence() []string
	GetSupportedEvidenceOk() ([]string, bool)
	HasSupportedEvidence() bool
	SetSupportedEvidence(v []string)
	GetSupportedIdentityDocuments() []string
	GetSupportedIdentityDocumentsOk() ([]string, bool)
	HasSupportedIdentityDocuments() bool
	SetSupportedIdentityDocuments(v []string)
	GetSupportedVerificationMethods() []string
	GetSupportedVerificationMethodsOk() ([]string, bool)
	HasSupportedVerificationMethods() bool
	SetSupportedVerificationMethods(v []string)
	GetSupportedVerifiedClaims() []string
	GetSupportedVerifiedClaimsOk() ([]string, bool)
	HasSupportedVerifiedClaims() bool
	SetSupportedVerifiedClaims(v []string)
	HasAttributes() bool
	GetNbfOptional() bool
	GetNbfOptionalOk() (*bool, bool)
	HasNbfOptional() bool
	SetNbfOptional(v bool)
	GetIssSuppressed() bool
	GetIssSuppressedOk() (*bool, bool)
	HasIssSuppressed() bool
	SetIssSuppressed(v bool)
	GetSupportedCustomClientMetadata() []string
	GetSupportedCustomClientMetadataOk() ([]string, bool)
	HasSupportedCustomClientMetadata() bool
	SetSupportedCustomClientMetadata(v []string)
	GetTokenExpirationLinked() bool
	GetTokenExpirationLinkedOk() (*bool, bool)
	HasTokenExpirationLinked() bool
	SetTokenExpirationLinked(v bool)
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
	GetHsmEnabled() bool
	GetHsmEnabledOk() (*bool, bool)
	HasHsmEnabled() bool
	SetHsmEnabled(v bool)
	HasHsks() bool
	GetGrantManagementEndpoint() string
	GetGrantManagementEndpointOk() (*string, bool)
	HasGrantManagementEndpoint() bool
	SetGrantManagementEndpoint(v string)
	GetGrantManagementActionRequired() bool
	GetGrantManagementActionRequiredOk() (*bool, bool)
	HasGrantManagementActionRequired() bool
	SetGrantManagementActionRequired(v bool)
	GetUnauthorizedOnClientConfigSupported() bool
	GetUnauthorizedOnClientConfigSupportedOk() (*bool, bool)
	HasUnauthorizedOnClientConfigSupported() bool
	SetUnauthorizedOnClientConfigSupported(v bool)
	GetDcrScopeUsedAsRequestable() bool
	GetDcrScopeUsedAsRequestableOk() (*bool, bool)
	HasDcrScopeUsedAsRequestable() bool
	SetDcrScopeUsedAsRequestable(v bool)
	GetEndSessionEndpoint() string
	GetEndSessionEndpointOk() (*string, bool)
	HasEndSessionEndpoint() bool
	SetEndSessionEndpoint(v string)
	GetLoopbackRedirectionUriVariable() bool
	GetLoopbackRedirectionUriVariableOk() (*bool, bool)
	HasLoopbackRedirectionUriVariable() bool
	SetLoopbackRedirectionUriVariable(v bool)
	GetRequestObjectAudienceChecked() bool
	GetRequestObjectAudienceCheckedOk() (*bool, bool)
	HasRequestObjectAudienceChecked() bool
	SetRequestObjectAudienceChecked(v bool)
	GetAccessTokenForExternalAttachmentEmbedded() bool
	GetAccessTokenForExternalAttachmentEmbeddedOk() (*bool, bool)
	HasAccessTokenForExternalAttachmentEmbedded() bool
	SetAccessTokenForExternalAttachmentEmbedded(v bool)
	GetAuthorityHints() []string
	GetAuthorityHintsOk() ([]string, bool)
	HasAuthorityHints() bool
	SetAuthorityHints(v []string)
	GetFederationEnabled() bool
	GetFederationEnabledOk() (*bool, bool)
	HasFederationEnabled() bool
	SetFederationEnabled(v bool)
	GetFederationJwks() string
	GetFederationJwksOk() (*string, bool)
	HasFederationJwks() bool
	SetFederationJwks(v string)
	GetFederationSignatureKeyId() string
	GetFederationSignatureKeyIdOk() (*string, bool)
	HasFederationSignatureKeyId() bool
	SetFederationSignatureKeyId(v string)
	GetFederationConfigurationDuration() int32
	GetFederationConfigurationDurationOk() (*int32, bool)
	HasFederationConfigurationDuration() bool
	SetFederationConfigurationDuration(v int32)
	GetFederationRegistrationEndpoint() string
	GetFederationRegistrationEndpointOk() (*string, bool)
	HasFederationRegistrationEndpoint() bool
	SetFederationRegistrationEndpoint(v string)
	GetOrganizationName() string
	GetOrganizationNameOk() (*string, bool)
	HasOrganizationName() bool
	SetOrganizationName(v string)
	GetPredefinedTransformedClaims() string
	GetPredefinedTransformedClaimsOk() (*string, bool)
	HasPredefinedTransformedClaims() bool
	SetPredefinedTransformedClaims(v string)
	GetRefreshTokenIdempotent() bool
	GetRefreshTokenIdempotentOk() (*bool, bool)
	HasRefreshTokenIdempotent() bool
	SetRefreshTokenIdempotent(v bool)
	GetSignedJwksUri() string
	GetSignedJwksUriOk() (*string, bool)
	HasSignedJwksUri() bool
	SetSignedJwksUri(v string)
	HasSupportedAttachments() bool
	GetSupportedDigestAlgorithms() []string
	GetSupportedDigestAlgorithmsOk() ([]string, bool)
	HasSupportedDigestAlgorithms() bool
	SetSupportedDigestAlgorithms(v []string)
	GetSupportedDocuments() []string
	GetSupportedDocumentsOk() ([]string, bool)
	HasSupportedDocuments() bool
	SetSupportedDocuments(v []string)
	GetSupportedDocumentsMethods() []string
	GetSupportedDocumentsMethodsOk() ([]string, bool)
	HasSupportedDocumentsMethods() bool
	SetSupportedDocumentsMethods(v []string)
	GetSupportedDocumentsValidationMethods() []string
	GetSupportedDocumentsValidationMethodsOk() ([]string, bool)
	HasSupportedDocumentsValidationMethods() bool
	SetSupportedDocumentsValidationMethods(v []string)
	GetSupportedDocumentsVerificationMethods() []string
	GetSupportedDocumentsVerificationMethodsOk() ([]string, bool)
	HasSupportedDocumentsVerificationMethods() bool
	SetSupportedDocumentsVerificationMethods(v []string)
	GetSupportedElectronicRecords() []string
	GetSupportedElectronicRecordsOk() ([]string, bool)
	HasSupportedElectronicRecords() bool
	SetSupportedElectronicRecords(v []string)
	HasSupportedClientRegistrationTypes() bool
	GetTokenExchangeByIdentifiableClientsOnly() bool
	GetTokenExchangeByIdentifiableClientsOnlyOk() (*bool, bool)
	HasTokenExchangeByIdentifiableClientsOnly() bool
	SetTokenExchangeByIdentifiableClientsOnly(v bool)
	GetTokenExchangeByConfidentialClientsOnly() bool
	GetTokenExchangeByConfidentialClientsOnlyOk() (*bool, bool)
	HasTokenExchangeByConfidentialClientsOnly() bool
	SetTokenExchangeByConfidentialClientsOnly(v bool)
	GetTokenExchangeByPermittedClientsOnly() bool
	GetTokenExchangeByPermittedClientsOnlyOk() (*bool, bool)
	HasTokenExchangeByPermittedClientsOnly() bool
	SetTokenExchangeByPermittedClientsOnly(v bool)
	GetTokenExchangeEncryptedJwtRejected() bool
	GetTokenExchangeEncryptedJwtRejectedOk() (*bool, bool)
	HasTokenExchangeEncryptedJwtRejected() bool
	SetTokenExchangeEncryptedJwtRejected(v bool)
	GetTokenExchangeUnsignedJwtRejected() bool
	GetTokenExchangeUnsignedJwtRejectedOk() (*bool, bool)
	HasTokenExchangeUnsignedJwtRejected() bool
	SetTokenExchangeUnsignedJwtRejected(v bool)
	GetJwtGrantByIdentifiableClientsOnly() bool
	GetJwtGrantByIdentifiableClientsOnlyOk() (*bool, bool)
	HasJwtGrantByIdentifiableClientsOnly() bool
	SetJwtGrantByIdentifiableClientsOnly(v bool)
	GetJwtGrantEncryptedJwtRejected() bool
	GetJwtGrantEncryptedJwtRejectedOk() (*bool, bool)
	HasJwtGrantEncryptedJwtRejected() bool
	SetJwtGrantEncryptedJwtRejected(v bool)
	GetJwtGrantUnsignedJwtRejected() bool
	GetJwtGrantUnsignedJwtRejectedOk() (*bool, bool)
	HasJwtGrantUnsignedJwtRejected() bool
	SetJwtGrantUnsignedJwtRejected(v bool)
	GetDcrDuplicateSoftwareIdBlocked() bool
	GetDcrDuplicateSoftwareIdBlockedOk() (*bool, bool)
	HasDcrDuplicateSoftwareIdBlocked() bool
	SetDcrDuplicateSoftwareIdBlocked(v bool)
	HasTrustAnchors() bool
	GetOpenidDroppedOnRefreshWithoutOfflineAccess() bool
	GetOpenidDroppedOnRefreshWithoutOfflineAccessOk() (*bool, bool)
	HasOpenidDroppedOnRefreshWithoutOfflineAccess() bool
	SetOpenidDroppedOnRefreshWithoutOfflineAccess(v bool)
	GetSupportedDocumentsCheckMethods() []string
	GetSupportedDocumentsCheckMethodsOk() ([]string, bool)
	HasSupportedDocumentsCheckMethods() bool
	SetSupportedDocumentsCheckMethods(v []string)
	GetRsResponseSigned() bool
	GetRsResponseSignedOk() (*bool, bool)
	HasRsResponseSigned() bool
	SetRsResponseSigned(v bool)
	GetRsSignedRequestKeyId() string
	GetRsSignedRequestKeyIdOk() (*string, bool)
	HasRsSignedRequestKeyId() bool
	SetRsSignedRequestKeyId(v string)
	MarshalJSON() ([]byte, error)
	ToMap() (map[string]interface{}, error)
}
