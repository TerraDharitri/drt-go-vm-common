package builtInFunctions

import (
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/marshal"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

type dcdtModifyCreator struct {
	baseActiveHandler
	vmcommon.BlockchainDataProvider
	globalSettingsHandler vmcommon.GlobalMetadataHandler
	storageHandler        vmcommon.DCDTNFTStorageHandler
	rolesHandler          vmcommon.DCDTRoleHandler
	accounts              vmcommon.AccountsAdapter
	enableEpochsHandler   vmcommon.EnableEpochsHandler
	funcGasCost           uint64
	marshaller            marshal.Marshalizer
	mutExecution          sync.RWMutex
}

// NewDCDTModifyCreatorFunc returns the dcdt modify creator built-in function component
func NewDCDTModifyCreatorFunc(
	funcGasCost uint64,
	accounts vmcommon.AccountsAdapter,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	storageHandler vmcommon.DCDTNFTStorageHandler,
	rolesHandler vmcommon.DCDTRoleHandler,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) (*dcdtModifyCreator, error) {
	if check.IfNil(accounts) {
		return nil, ErrNilAccountsAdapter
	}
	if check.IfNil(globalSettingsHandler) {
		return nil, ErrNilGlobalSettingsHandler
	}
	if check.IfNil(enableEpochsHandler) {
		return nil, ErrNilEnableEpochsHandler
	}
	if check.IfNil(storageHandler) {
		return nil, ErrNilDCDTNFTStorageHandler
	}
	if check.IfNil(rolesHandler) {
		return nil, ErrNilRolesHandler
	}
	if check.IfNil(marshaller) {
		return nil, ErrNilMarshalizer
	}

	e := &dcdtModifyCreator{
		accounts:               accounts,
		globalSettingsHandler:  globalSettingsHandler,
		storageHandler:         storageHandler,
		rolesHandler:           rolesHandler,
		funcGasCost:            funcGasCost,
		enableEpochsHandler:    enableEpochsHandler,
		mutExecution:           sync.RWMutex{},
		BlockchainDataProvider: NewBlockchainDataProvider(),
		marshaller:             marshaller,
	}

	e.baseActiveHandler.activeHandler = func() bool {
		return enableEpochsHandler.IsFlagEnabled(DynamicDcdtFlag)
	}

	return e, nil
}

// ProcessBuiltinFunction saves the token type in the system account
func (e *dcdtModifyCreator) ProcessBuiltinFunction(acntSnd, _ vmcommon.UserAccountHandler, vmInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	err := checkUpdateArguments(vmInput, acntSnd, e.baseActiveHandler, 2, e.rolesHandler, core.DCDTRoleModifyCreator)
	if err != nil {
		return nil, err
	}

	e.mutExecution.RLock()
	funcGasCost := e.funcGasCost
	e.mutExecution.RUnlock()

	if vmInput.GasProvided < funcGasCost {
		return nil, ErrNotEnoughGas
	}

	dcdtInfo, err := getDcdtInfo(vmInput, acntSnd, e.storageHandler, e.globalSettingsHandler)
	if err != nil {
		return nil, err
	}

	metaDataVersion, _, err := getMetaDataVersion(dcdtInfo.dcdtData, e.enableEpochsHandler, e.marshaller)
	if err != nil {
		return nil, err
	}

	dcdtInfo.dcdtData.TokenMetaData.Creator = vmInput.CallerAddr
	metaDataVersion.Creator = e.CurrentRound()

	err = changeDcdtVersion(dcdtInfo.dcdtData, metaDataVersion, e.enableEpochsHandler, e.marshaller)
	if err != nil {
		return nil, err
	}

	err = saveDCDTMetaDataInfo(dcdtInfo, e.storageHandler, acntSnd, vmInput.ReturnCallAfterError)
	if err != nil {
		return nil, err
	}

	vmOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: vmInput.GasProvided - funcGasCost,
	}

	addDCDTEntryInVMOutput(vmOutput, []byte(core.DCDTModifyCreator), vmInput.Arguments[tokenIDIndex], dcdtInfo.dcdtData.TokenMetaData.Nonce, big.NewInt(0), [][]byte{vmInput.CallerAddr}...)

	return vmOutput, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtModifyCreator) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTModifyCreator
	e.mutExecution.Unlock()
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *dcdtModifyCreator) IsInterfaceNil() bool {
	return e == nil
}
