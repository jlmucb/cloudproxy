package tpm

import (
	"strconv"
)

// A TPMError is an error value from the TPM.
type opError uint32

// Error produces a string for the given TPM Error code
func (o opError) Error() string {
	if s, ok := opErrMsgs[o]; ok {
		return "tpm: " + s
	}

	return "tpm: unknown error code " + strconv.Itoa(int(o))
}

// These are the TPM error codes from the spec.
const (
	_                = iota
	AuthFail opError = iota
	BadIndex
	BadParameter
	AuditFailure
	ClearDisabled
	Deactivated
	Disabled
	DisabledCmd
	Fail
	BadOrdinal
	InstallDisabled
	InvalidKeyHandle
	KeyNotFound
	InappropriateEnc
	MigrateFail
	InvalidPCRInfo
	NoSpace
	NoSRK
	NotSealedBlob
	OwnerSet
	Resources
	ShortRandom
	NoSize // This is TPM_SIZE in the TPM spec, but Size is too generic for us.
	WrongPCRVal
	BadParamSize
	SHAThread
	SHAError
	FailedSelfTest
	Auth2Fail
	BadTag
	IOError
	EncryptError
	DecryptError
	InvalidAuthHandle
	NoEndorsement
	InvalidKeyUsage
	WrongEntityType
	InvalidPostInit
	InappropriateSig
	BadKeyProperty
	BadMigration
	BadScheme
	BadDatasize
	BadMode
	BadPresence
	BadVersion
	NoWrapTransport
	AuditFailUnsuccessful
	AuditFailSuccessful
	NotResetable
	NotLocal
	BadType
	InvalidResource
	NotFIPS
	InvalidFamily
	NoNVPermission
	RequiresSign
	KeyNotSupported
	AuthConflict
	AreaLocked
	BadLocality
	ReadOnly
	PerNoWrite
	FamilyCount
	WriteLocked
	BadAttributes
	InvalidStructure
	KeyOwnerControl
	BadCounter
	NotFullWrite
	ContextGap
	MaxNVWrites
	NoOperator
	ResourceMissing
	DelegateLock
	DelegateFamliy
	DelegateAdmin
	TransportNotExclusive
	OwnerControl
	DAAResources
	DAAInputData0
	DAAInputData1
	DAAIssuerSettings
	DAASettings
	DAAState
	DAAIssuerVailidity
	DAAWrongW
	BadHandle
	BadDelegate
	BadContext
	TooManyContexts
	MATicketSignature
	MADestination
	MASource
	MAAuthority
)

// opErrMsgs maps opError codes to their associated error strings. Normally, Go
// error messages must start with a lower-case character. However, in this case,
// these are the strings defined in the spec.
var opErrMsgs = map[opError]string{
	AuthFail:              "Authentication failed",
	BadIndex:              "The index to a PCR, DIR or other register is incorrect",
	BadParameter:          "One or more parameter is bad",
	AuditFailure:          "An operation completed successfully but the auditing of that operation failed",
	ClearDisabled:         "The clear disable flag is set and all clear operations now require physical access",
	Deactivated:           "The TPM is deactivated",
	Disabled:              "The TPM is disabled",
	DisabledCmd:           "The target command has been disabled",
	Fail:                  "The operation failed",
	BadOrdinal:            "The ordinal was unknown or inconsistent",
	InstallDisabled:       "The ability to install an owner is disabled",
	InvalidKeyHandle:      "The key handle can not be interpreted",
	KeyNotFound:           "The key handle points to an invalid key",
	InappropriateEnc:      "Unacceptable encryption scheme",
	MigrateFail:           "Migration authorization failed",
	InvalidPCRInfo:        "PCR information could not be interpreted",
	NoSpace:               "No room to load key",
	NoSRK:                 "There is no SRK set",
	NotSealedBlob:         "An encrypted blob is invalid or was not created by this TPM",
	OwnerSet:              "There is already an Owner",
	Resources:             "The TPM has insufficient internal resources to perform the requested action",
	ShortRandom:           "A random string was too short",
	NoSize:                "The TPM does not have the space to perform the operation",
	WrongPCRVal:           "The named PCR value does not match the current PCR value",
	BadParamSize:          "The paramSize argument to the command has the incorrect value",
	SHAThread:             "There is no existing SHA-1 thread",
	SHAError:              "The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error",
	FailedSelfTest:        "Self-test has failed and the TPM has shutdown",
	Auth2Fail:             "The authorization for the second key in a 2 key function failed authorization",
	BadTag:                "The tag value sent to for a command is invalid",
	IOError:               "An IO error occurred transmitting information to the TPM",
	EncryptError:          "The encryption process had a problem",
	DecryptError:          "The decryption process had a problem",
	InvalidAuthHandle:     "An invalid handle was used",
	NoEndorsement:         "The TPM does not have an EK installed",
	InvalidKeyUsage:       "The usage of a key is not allowed",
	WrongEntityType:       "The submitted entity type is not allowed",
	InvalidPostInit:       "The command was received in the wrong sequence relative to Init and a subsequent Startup",
	InappropriateSig:      "Signed data cannot include additional DER information",
	BadKeyProperty:        "The key properties in KEY_PARAMs are not supported by this TPM",
	BadMigration:          "The migration properties of this key are incorrect",
	BadScheme:             "The signature or encryption scheme for this key is incorrect or not permitted in this situation",
	BadDatasize:           "The size of the data (or blob) parameter is bad or inconsistent with the referenced key",
	BadMode:               "A mode parameter is bad, such as capArea or subCapArea for GetCapability, physicalPresence parameter for PhysicalPresence, or migrationType for CreateMigrationBlob",
	BadPresence:           "Either the physicalPresence or physicalPresenceLock bits have the wrong value",
	BadVersion:            "The TPM cannot perform this version of the capability",
	NoWrapTransport:       "The TPM does not allow for wrapped transport sessions",
	AuditFailUnsuccessful: "TPM audit construction failed and th eunderlying command was returning a failure code also",
	AuditFailSuccessful:   "TPM audit construction failed and the underlying command was returning success",
	NotResetable:          "Attempt to reset a PCR register that does not have the resettable attribute",
	NotLocal:              "Attempt to reset a PCR register that requires locality and locality modifier not part of command transport",
	BadType:               "Make identity blob not properly typed",
	InvalidResource:       "When saving context identified resource type does not match actual resource",
	NotFIPS:               "The TPM is attempting to execute a command only available when in FIPS mode",
	InvalidFamily:         "The command is attempting to use an invalid family ID",
	NoNVPermission:        "The permission to manipulate the NV storage is not available",
	RequiresSign:          "The operation requires a signed command",
	KeyNotSupported:       "Wrong operation to load an NV key",
	AuthConflict:          "NV_LoadKey blob requires both owner and blob authorization",
	AreaLocked:            "The NV area is locked and not writeable",
	BadLocality:           "The locality is incorrect for the attempted operation",
	ReadOnly:              "The NV area is read only and can't be written to",
	PerNoWrite:            "There is no protection on the write to the NV area",
	FamilyCount:           "The family count value does not match",
	WriteLocked:           "The NV area has already been written to",
	BadAttributes:         "The NV area attributes conflict",
	InvalidStructure:      "The structure tag and version are invalid or inconsistent",
	KeyOwnerControl:       "The key is under control of the TPM Owner and can only be evicted by the TPM Owner",
	BadCounter:            "The counter handle is incorrect",
	NotFullWrite:          "The write is not a complete write of the area",
	ContextGap:            "The gap between saved context counts is too large",
	MaxNVWrites:           "The maximum number of NV writes without an owner has been exceeded",
	NoOperator:            "No operator AuthData value is set",
	ResourceMissing:       "The resource pointed to by context is not loaded",
	DelegateLock:          "The delegate administration is locked",
	DelegateFamliy:        "Attempt to manage a family other than the delegated family",
	DelegateAdmin:         "Delegation table management not enabled",
	TransportNotExclusive: "There was a command executed outside of an exclusive transport session",
	OwnerControl:          "Attempt to context save a owner evict controlled key",
	DAAResources:          "The DAA command has no resources available to execute the command",
	DAAInputData0:         "The consistency check on DAA parameter inputData0 has failed",
	DAAInputData1:         "The consistency check on DAA parameter inputData1 has failed",
	DAAIssuerSettings:     "The consistency check on DAA_issuerSettings has failed",
	DAASettings:           "The consistency check on DAA_tpmSpecific has failed",
	DAAState:              "The atomic process indicated by the submitted DAA command is not the expected process",
	DAAIssuerVailidity:    "The issuer's validity check has detected an inconsistency",
	DAAWrongW:             "The consistency check on w has failed",
	BadHandle:             "The handle is incorrect",
	BadDelegate:           "Delegation is not correct",
	BadContext:            "The context blob is invalid",
	TooManyContexts:       "Too many contexts held by the TPM",
	MATicketSignature:     "Migration authority signature validation failure",
	MADestination:         "Migration destination not authenticated",
	MASource:              "Migration source incorrect",
	MAAuthority:           "Incorrect migration authority",
}
