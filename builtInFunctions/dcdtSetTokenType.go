package builtInFunctions

import (
	"bytes"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/marshal"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

const (
	tokenIDindex   = 0
	tokenTypeIndex = 1
)

type dcdtSetTokenType struct {
	baseActiveHandler
	globalSettingsHandler vmcommon.GlobalMetadataHandler
	accounts              vmcommon.AccountsAdapter
	marshaller            marshal.Marshalizer
}

// NewDCDTSetTokenTypeFunc returns the dcdt set token type built-in function component
func NewDCDTSetTokenTypeFunc(
	accounts vmcommon.AccountsAdapter,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	marshaller marshal.Marshalizer,
	activeHandler func() bool,
) (*dcdtSetTokenType, error) {
	if check.IfNil(accounts) {
		return nil, ErrNilAccountsAdapter
	}
	if check.IfNil(marshaller) {
		return nil, ErrNilMarshalizer
	}
	if check.IfNil(globalSettingsHandler) {
		return nil, ErrNilGlobalSettingsHandler
	}
	if activeHandler == nil {
		return nil, ErrNilActiveHandler
	}

	e := &dcdtSetTokenType{
		accounts:              accounts,
		globalSettingsHandler: globalSettingsHandler,
		marshaller:            marshaller,
	}

	e.baseActiveHandler.activeHandler = activeHandler

	return e, nil
}

// ProcessBuiltinFunction saves the token type in the system account
func (e *dcdtSetTokenType) ProcessBuiltinFunction(_, _ vmcommon.UserAccountHandler, vmInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	if vmInput == nil {
		return nil, ErrNilVmInput
	}
	if vmInput.CallValue.Cmp(zero) != 0 {
		return nil, ErrBuiltInFunctionCalledWithValue
	}
	if len(vmInput.Arguments) != 2 {
		return nil, ErrInvalidArguments
	}
	if !bytes.Equal(vmInput.CallerAddr, core.DCDTSCAddress) {
		return nil, ErrAddressIsNotDCDTSystemSC
	}
	if !vmcommon.IsSystemAccountAddress(vmInput.RecipientAddr) {
		return nil, ErrOnlySystemAccountAccepted
	}

	dcdtTokenKey := append([]byte(baseDCDTKeyPrefix), vmInput.Arguments[tokenIDindex]...)
	tokenType, err := core.ConvertDCDTTypeToUint32(string(vmInput.Arguments[tokenTypeIndex]))
	if err != nil {
		return nil, err
	}

	err = e.globalSettingsHandler.SetTokenType(dcdtTokenKey, tokenType)
	if err != nil {
		return nil, err
	}

	vmOutput := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	return vmOutput, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtSetTokenType) SetNewGasConfig(_ *vmcommon.GasCost) {
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *dcdtSetTokenType) IsInterfaceNil() bool {
	return e == nil
}
