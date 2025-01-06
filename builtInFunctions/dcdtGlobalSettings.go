package builtInFunctions

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/marshal"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

// DCDTTypeForGlobalSettingsHandler is needed because if 0 is retrieved from the global settings handler,
// it means either that the type is not set or that the type is fungible. This will solve the ambiguity.
type DCDTTypeForGlobalSettingsHandler uint32

const (
	notSet DCDTTypeForGlobalSettingsHandler = iota
	fungible
	nonFungible
	nonFungibleV2
	metaFungible
	semiFungible
	dynamicNFT
	dynamicSFT
	dynamicMeta
)

type dcdtGlobalSettings struct {
	baseActiveHandler
	keyPrefix  []byte
	set        bool
	accounts   vmcommon.AccountsAdapter
	marshaller marshal.Marshalizer
	function   string
}

// NewDCDTGlobalSettingsFunc returns the dcdt pause/un-pause built-in function component
func NewDCDTGlobalSettingsFunc(
	accounts vmcommon.AccountsAdapter,
	marshaller marshal.Marshalizer,
	set bool,
	function string,
	activeHandler func() bool,
) (*dcdtGlobalSettings, error) {
	if check.IfNil(accounts) {
		return nil, ErrNilAccountsAdapter
	}
	if check.IfNil(marshaller) {
		return nil, ErrNilMarshalizer
	}
	if activeHandler == nil {
		return nil, ErrNilActiveHandler
	}
	if !isCorrectFunction(function) {
		return nil, ErrInvalidArguments
	}

	e := &dcdtGlobalSettings{
		keyPrefix:  []byte(baseDCDTKeyPrefix),
		set:        set,
		accounts:   accounts,
		marshaller: marshaller,
		function:   function,
	}

	e.baseActiveHandler.activeHandler = activeHandler

	return e, nil
}

func isCorrectFunction(function string) bool {
	switch function {
	case core.BuiltInFunctionDCDTPause, core.BuiltInFunctionDCDTUnPause, core.BuiltInFunctionDCDTSetLimitedTransfer, core.BuiltInFunctionDCDTUnSetLimitedTransfer:
		return true
	case vmcommon.BuiltInFunctionDCDTSetBurnRoleForAll, vmcommon.BuiltInFunctionDCDTUnSetBurnRoleForAll:
		return true
	default:
		return false
	}
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtGlobalSettings) SetNewGasConfig(_ *vmcommon.GasCost) {
}

// ProcessBuiltinFunction resolves DCDT pause function call
func (e *dcdtGlobalSettings) ProcessBuiltinFunction(
	_, _ vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	if vmInput == nil {
		return nil, ErrNilVmInput
	}
	if vmInput.CallValue.Cmp(zero) != 0 {
		return nil, ErrBuiltInFunctionCalledWithValue
	}
	if len(vmInput.Arguments) != 1 {
		return nil, ErrInvalidArguments
	}
	if !bytes.Equal(vmInput.CallerAddr, core.DCDTSCAddress) {
		return nil, ErrAddressIsNotDCDTSystemSC
	}
	if !vmcommon.IsSystemAccountAddress(vmInput.RecipientAddr) {
		return nil, ErrOnlySystemAccountAccepted
	}

	dcdtTokenKey := append(e.keyPrefix, vmInput.Arguments[0]...)

	err := e.toggleSetting(dcdtTokenKey)
	if err != nil {
		return nil, err
	}

	vmOutput := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	return vmOutput, nil
}

func (e *dcdtGlobalSettings) toggleSetting(dcdtTokenKey []byte) error {
	systemSCAccount, err := getSystemAccount(e.accounts)
	if err != nil {
		return err
	}

	dcdtMetaData, err := e.GetGlobalMetadata(dcdtTokenKey)
	if err != nil {
		return err
	}

	switch e.function {
	case core.BuiltInFunctionDCDTSetLimitedTransfer, core.BuiltInFunctionDCDTUnSetLimitedTransfer:
		dcdtMetaData.LimitedTransfer = e.set
	case core.BuiltInFunctionDCDTPause, core.BuiltInFunctionDCDTUnPause:
		dcdtMetaData.Paused = e.set
	case vmcommon.BuiltInFunctionDCDTUnSetBurnRoleForAll, vmcommon.BuiltInFunctionDCDTSetBurnRoleForAll:
		dcdtMetaData.BurnRoleForAll = e.set
	}

	err = systemSCAccount.AccountDataHandler().SaveKeyValue(dcdtTokenKey, dcdtMetaData.ToBytes())
	if err != nil {
		return err
	}

	return e.accounts.SaveAccount(systemSCAccount)
}

func getSystemAccount(accounts vmcommon.AccountsAdapter) (vmcommon.UserAccountHandler, error) {
	systemSCAccount, err := accounts.LoadAccount(vmcommon.SystemAccountAddress)
	if err != nil {
		return nil, err
	}

	userAcc, ok := systemSCAccount.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, ErrWrongTypeAssertion
	}

	return userAcc, nil
}

// IsPaused returns true if the dcdtTokenKey (prefixed) is paused
func (e *dcdtGlobalSettings) IsPaused(dcdtTokenKey []byte) bool {
	dcdtMetadata, err := e.GetGlobalMetadata(dcdtTokenKey)
	if err != nil {
		return false
	}

	return dcdtMetadata.Paused
}

// IsLimitedTransfer returns true if the dcdtTokenKey (prefixed) is with limited transfer
func (e *dcdtGlobalSettings) IsLimitedTransfer(dcdtTokenKey []byte) bool {
	dcdtMetadata, err := e.GetGlobalMetadata(dcdtTokenKey)
	if err != nil {
		return false
	}

	return dcdtMetadata.LimitedTransfer
}

// IsBurnForAll returns true if the dcdtTokenKey (prefixed) is with burn for all
func (e *dcdtGlobalSettings) IsBurnForAll(dcdtTokenKey []byte) bool {
	dcdtMetadata, err := e.GetGlobalMetadata(dcdtTokenKey)
	if err != nil {
		return false
	}

	return dcdtMetadata.BurnRoleForAll
}

// IsSenderOrDestinationWithTransferRole returns true if we have transfer role on the system account
func (e *dcdtGlobalSettings) IsSenderOrDestinationWithTransferRole(sender, destination, tokenID []byte) bool {
	if !e.activeHandler() {
		return false
	}

	systemAcc, err := getSystemAccount(e.accounts)
	if err != nil {
		return false
	}

	dcdtTokenTransferRoleKey := append(transferAddressesKeyPrefix, tokenID...)
	addresses, _, err := getDCDTRolesForAcnt(e.marshaller, systemAcc, dcdtTokenTransferRoleKey)
	if err != nil {
		return false
	}

	for _, address := range addresses.Roles {
		if bytes.Equal(address, sender) || bytes.Equal(address, destination) {
			return true
		}
	}

	return false
}

// GetGlobalMetadata returns the global metadata for the dcdtTokenKey
func (e *dcdtGlobalSettings) GetGlobalMetadata(dcdtTokenKey []byte) (*DCDTGlobalMetadata, error) {
	systemSCAccount, err := getSystemAccount(e.accounts)
	if err != nil {
		return nil, err
	}

	val, _, err := systemSCAccount.AccountDataHandler().RetrieveValue(dcdtTokenKey)
	if core.IsGetNodeFromDBError(err) {
		return nil, err
	}
	dcdtMetaData := DCDTGlobalMetadataFromBytes(val)
	return &dcdtMetaData, nil
}

// GetTokenType returns the token type for the dcdtTokenKey
func (e *dcdtGlobalSettings) GetTokenType(dcdtTokenKey []byte) (uint32, error) {
	dcdtMetaData, err := e.GetGlobalMetadata(dcdtTokenKey)
	if err != nil {
		return 0, err
	}

	tokenType, err := convertToDCDTTokenType(uint32(dcdtMetaData.TokenType))
	if errors.Is(err, ErrTypeNotSetInsideGlobalSettingsHandler) {
		return uint32(core.NonFungible), nil
	}
	if err != nil {
		return 0, err
	}

	return tokenType, nil
}

// SetTokenType sets the token type for the dcdtTokenKey
func (e *dcdtGlobalSettings) SetTokenType(dcdtTokenKey []byte, tokenType uint32) error {
	globalSettingsTokenType, err := convertToGlobalSettingsHandlerTokenType(tokenType)
	if err != nil {
		return err
	}

	systemAccount, err := getSystemAccount(e.accounts)
	if err != nil {
		return err
	}

	val, _, err := systemAccount.AccountDataHandler().RetrieveValue(dcdtTokenKey)
	if core.IsGetNodeFromDBError(err) {
		return err
	}
	dcdtMetaData := DCDTGlobalMetadataFromBytes(val)
	dcdtMetaData.TokenType = byte(globalSettingsTokenType)

	err = systemAccount.AccountDataHandler().SaveKeyValue(dcdtTokenKey, dcdtMetaData.ToBytes())
	if err != nil {
		return err
	}

	return e.accounts.SaveAccount(systemAccount)
}

func convertToGlobalSettingsHandlerTokenType(dcdtType uint32) (uint32, error) {
	switch dcdtType {
	case uint32(core.Fungible):
		return uint32(fungible), nil
	case uint32(core.NonFungible):
		return uint32(nonFungible), nil
	case uint32(core.NonFungibleV2):
		return uint32(nonFungibleV2), nil
	case uint32(core.MetaFungible):
		return uint32(metaFungible), nil
	case uint32(core.SemiFungible):
		return uint32(semiFungible), nil
	case uint32(core.DynamicNFT):
		return uint32(dynamicNFT), nil
	case uint32(core.DynamicSFT):
		return uint32(dynamicSFT), nil
	case uint32(core.DynamicMeta):
		return uint32(dynamicMeta), nil
	default:
		return math.MaxUint32, fmt.Errorf("invalid dcdt type: %d", dcdtType)
	}
}

func convertToDCDTTokenType(dcdtType uint32) (uint32, error) {
	switch DCDTTypeForGlobalSettingsHandler(dcdtType) {
	case notSet:
		return 0, ErrTypeNotSetInsideGlobalSettingsHandler
	case fungible:
		return uint32(core.Fungible), nil
	case nonFungible:
		return uint32(core.NonFungible), nil
	case nonFungibleV2:
		return uint32(core.NonFungibleV2), nil
	case metaFungible:
		return uint32(core.MetaFungible), nil
	case semiFungible:
		return uint32(core.SemiFungible), nil
	case dynamicNFT:
		return uint32(core.DynamicNFT), nil
	case dynamicSFT:
		return uint32(core.DynamicSFT), nil
	case dynamicMeta:
		return uint32(core.DynamicMeta), nil
	default:
		return math.MaxUint32, fmt.Errorf("invalid dcdt type: %d", dcdtType)
	}
}

// IsInterfaceNil returns true if underlying object in nil
func (e *dcdtGlobalSettings) IsInterfaceNil() bool {
	return e == nil
}
