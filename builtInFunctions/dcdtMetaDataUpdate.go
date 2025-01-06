package builtInFunctions

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/marshal"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

type dcdtMetaDataUpdate struct {
	baseActiveHandler
	vmcommon.BlockchainDataProvider
	funcGasCost           uint64
	globalSettingsHandler vmcommon.GlobalMetadataHandler
	storageHandler        vmcommon.DCDTNFTStorageHandler
	rolesHandler          vmcommon.DCDTRoleHandler
	accounts              vmcommon.AccountsAdapter
	enableEpochsHandler   vmcommon.EnableEpochsHandler
	gasConfig             vmcommon.BaseOperationCost
	marshaller            marshal.Marshalizer
	mutExecution          sync.RWMutex
}

// NewDCDTMetaDataUpdateFunc returns the dcdt meta data update built-in function component
func NewDCDTMetaDataUpdateFunc(
	funcGasCost uint64,
	gasConfig vmcommon.BaseOperationCost,
	accounts vmcommon.AccountsAdapter,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	storageHandler vmcommon.DCDTNFTStorageHandler,
	rolesHandler vmcommon.DCDTRoleHandler,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) (*dcdtMetaDataUpdate, error) {
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

	e := &dcdtMetaDataUpdate{
		accounts:               accounts,
		globalSettingsHandler:  globalSettingsHandler,
		storageHandler:         storageHandler,
		rolesHandler:           rolesHandler,
		enableEpochsHandler:    enableEpochsHandler,
		funcGasCost:            funcGasCost,
		gasConfig:              gasConfig,
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
func (e *dcdtMetaDataUpdate) ProcessBuiltinFunction(acntSnd, _ vmcommon.UserAccountHandler, vmInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	err := checkUpdateArguments(vmInput, acntSnd, e.baseActiveHandler, 7, e.rolesHandler, core.DCDTRoleNFTUpdate)
	if err != nil {
		return nil, err
	}

	totalLengthDifference := lenArgs(vmInput.Arguments)

	dcdtInfo, err := getDcdtInfo(vmInput, acntSnd, e.storageHandler, e.globalSettingsHandler)
	if err != nil {
		return nil, err
	}

	currentRound := e.CurrentRound()
	metaDataVersion, _, err := getMetaDataVersion(dcdtInfo.dcdtData, e.enableEpochsHandler, e.marshaller)
	if err != nil {
		return nil, err
	}

	if len(vmInput.Arguments[nameIndex]) != 0 {
		totalLengthDifference -= len(dcdtInfo.dcdtData.TokenMetaData.Name)
		dcdtInfo.dcdtData.TokenMetaData.Name = vmInput.Arguments[nameIndex]
		metaDataVersion.Name = currentRound
	}
	totalLengthDifference -= len(dcdtInfo.dcdtData.TokenMetaData.Creator)
	dcdtInfo.dcdtData.TokenMetaData.Creator = vmInput.CallerAddr
	metaDataVersion.Creator = currentRound

	if len(vmInput.Arguments[royaltiesIndex]) != 0 {
		totalLengthDifference -= len(vmInput.Arguments[royaltiesIndex])
		royalties := uint32(big.NewInt(0).SetBytes(vmInput.Arguments[royaltiesIndex]).Uint64())
		if royalties > core.MaxRoyalty {
			return nil, fmt.Errorf("%w, invalid max royality value", ErrInvalidArguments)
		}
		dcdtInfo.dcdtData.TokenMetaData.Royalties = royalties
		metaDataVersion.Royalties = currentRound
	}

	if len(vmInput.Arguments[hashIndex]) != 0 {
		totalLengthDifference -= len(dcdtInfo.dcdtData.TokenMetaData.Hash)
		dcdtInfo.dcdtData.TokenMetaData.Hash = vmInput.Arguments[hashIndex]
		metaDataVersion.Hash = currentRound
	}

	if len(vmInput.Arguments[attributesIndex]) != 0 {
		totalLengthDifference -= len(dcdtInfo.dcdtData.TokenMetaData.Attributes)
		dcdtInfo.dcdtData.TokenMetaData.Attributes = vmInput.Arguments[attributesIndex]
		metaDataVersion.Attributes = currentRound
	}

	if len(vmInput.Arguments[urisStartIndex]) != 0 {
		for _, uri := range dcdtInfo.dcdtData.TokenMetaData.URIs {
			totalLengthDifference -= len(uri)
		}

		dcdtInfo.dcdtData.TokenMetaData.URIs = vmInput.Arguments[urisStartIndex:]
		metaDataVersion.URIs = currentRound
	}

	if totalLengthDifference < 0 {
		totalLengthDifference = 0
	}

	e.mutExecution.RLock()
	gasToUse := uint64(totalLengthDifference)*e.gasConfig.StorePerByte + e.funcGasCost
	e.mutExecution.RUnlock()
	if vmInput.GasProvided < gasToUse {
		return nil, ErrNotEnoughGas
	}

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

	dcdtDataBytes, err := e.marshaller.Marshal(dcdtInfo.dcdtData)
	if err != nil {
		log.Warn("dcdtMetaDataUpdate.ProcessBuiltinFunction: cannot marshall dcdt data for log", "error", err)
	}

	addDCDTEntryInVMOutput(vmOutput, []byte(core.DCDTMetaDataUpdate), vmInput.Arguments[0], dcdtInfo.dcdtData.TokenMetaData.Nonce, big.NewInt(0), vmInput.CallerAddr, dcdtDataBytes)

	return vmOutput, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtMetaDataUpdate) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTNFTUpdate
	e.gasConfig = gasCost.BaseOperationCost
	e.mutExecution.Unlock()
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *dcdtMetaDataUpdate) IsInterfaceNil() bool {
	return e == nil
}
