package builtInFunctions

import (
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/marshal"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

const uriStartIndex = 2

type dcdtSetNewURIs struct {
	baseActiveHandler
	vmcommon.BlockchainDataProvider
	globalSettingsHandler vmcommon.GlobalMetadataHandler
	storageHandler        vmcommon.DCDTNFTStorageHandler
	rolesHandler          vmcommon.DCDTRoleHandler
	accounts              vmcommon.AccountsAdapter
	enableEpochsHandler   vmcommon.EnableEpochsHandler
	funcGasCost           uint64
	gasConfig             vmcommon.BaseOperationCost
	marshaller            marshal.Marshalizer
	mutExecution          sync.RWMutex
}

// NewDCDTSetNewURIsFunc returns the dcdt set new URIs built-in function component
func NewDCDTSetNewURIsFunc(
	funcGasCost uint64,
	gasConfig vmcommon.BaseOperationCost,
	accounts vmcommon.AccountsAdapter,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	storageHandler vmcommon.DCDTNFTStorageHandler,
	rolesHandler vmcommon.DCDTRoleHandler,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) (*dcdtSetNewURIs, error) {
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

	e := &dcdtSetNewURIs{
		accounts:               accounts,
		globalSettingsHandler:  globalSettingsHandler,
		storageHandler:         storageHandler,
		rolesHandler:           rolesHandler,
		funcGasCost:            funcGasCost,
		gasConfig:              gasConfig,
		mutExecution:           sync.RWMutex{},
		enableEpochsHandler:    enableEpochsHandler,
		BlockchainDataProvider: NewBlockchainDataProvider(),
		marshaller:             marshaller,
	}

	e.baseActiveHandler.activeHandler = func() bool {
		return enableEpochsHandler.IsFlagEnabled(DynamicDcdtFlag)
	}

	return e, nil
}

// ProcessBuiltinFunction saves the token type in the system account
func (e *dcdtSetNewURIs) ProcessBuiltinFunction(acntSnd, _ vmcommon.UserAccountHandler, vmInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	err := checkUpdateArguments(vmInput, acntSnd, e.baseActiveHandler, 3, e.rolesHandler, core.DCDTRoleSetNewURI)
	if err != nil {
		return nil, err
	}

	dcdtInfo, err := getDcdtInfo(vmInput, acntSnd, e.storageHandler, e.globalSettingsHandler)
	if err != nil {
		return nil, err
	}

	oldURIsLen := lenArgs(dcdtInfo.dcdtData.TokenMetaData.URIs)
	newURIsLen := lenArgs(vmInput.Arguments[uriStartIndex:])
	difference := newURIsLen - oldURIsLen
	if difference < 0 {
		difference = 0
	}

	e.mutExecution.RLock()
	gasToUse := uint64(difference)*e.gasConfig.StorePerByte + e.funcGasCost
	e.mutExecution.RUnlock()

	if vmInput.GasProvided < gasToUse {
		return nil, ErrNotEnoughGas
	}

	metaDataVersion, _, err := getMetaDataVersion(dcdtInfo.dcdtData, e.enableEpochsHandler, e.marshaller)
	if err != nil {
		return nil, err
	}

	dcdtInfo.dcdtData.TokenMetaData.URIs = vmInput.Arguments[uriStartIndex:]
	metaDataVersion.URIs = e.CurrentRound()

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
		GasRemaining: vmInput.GasProvided - gasToUse,
	}

	extraTopics := append([][]byte{vmInput.CallerAddr}, vmInput.Arguments[uriStartIndex:]...)
	addDCDTEntryInVMOutput(vmOutput, []byte(core.DCDTSetNewURIs), vmInput.Arguments[0], dcdtInfo.dcdtData.TokenMetaData.Nonce, big.NewInt(0), extraTopics...)

	return vmOutput, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtSetNewURIs) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTNFTSetNewURIs
	e.gasConfig = gasCost.BaseOperationCost
	e.mutExecution.Unlock()
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *dcdtSetNewURIs) IsInterfaceNil() bool {
	return e == nil
}
