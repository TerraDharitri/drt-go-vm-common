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

const (
	tokenIDIndex      = 0
	nonceIndex        = 1
	newRoyaltiesIndex = 2
)

type dcdtModifyRoyalties struct {
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

// NewDCDTModifyRoyaltiesFunc returns the dcdt modify royalties built-in function component
func NewDCDTModifyRoyaltiesFunc(
	funcGasCost uint64,
	accounts vmcommon.AccountsAdapter,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	storageHandler vmcommon.DCDTNFTStorageHandler,
	rolesHandler vmcommon.DCDTRoleHandler,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) (*dcdtModifyRoyalties, error) {
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

	e := &dcdtModifyRoyalties{
		accounts:               accounts,
		globalSettingsHandler:  globalSettingsHandler,
		storageHandler:         storageHandler,
		rolesHandler:           rolesHandler,
		funcGasCost:            funcGasCost,
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
func (e *dcdtModifyRoyalties) ProcessBuiltinFunction(acntSnd, _ vmcommon.UserAccountHandler, vmInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	err := checkUpdateArguments(vmInput, acntSnd, e.baseActiveHandler, 3, e.rolesHandler, core.DCDTRoleModifyRoyalties)
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

	newRoyalties := uint32(big.NewInt(0).SetBytes(vmInput.Arguments[newRoyaltiesIndex]).Uint64())
	if newRoyalties > core.MaxRoyalty {
		return nil, fmt.Errorf("%w, invalid max royality value", ErrInvalidArguments)
	}

	metaDataVersion, _, err := getMetaDataVersion(dcdtInfo.dcdtData, e.enableEpochsHandler, e.marshaller)
	if err != nil {
		return nil, err
	}

	dcdtInfo.dcdtData.TokenMetaData.Royalties = newRoyalties
	metaDataVersion.Royalties = e.CurrentRound()

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

	extraTopics := [][]byte{vmInput.CallerAddr, vmInput.Arguments[newRoyaltiesIndex]}
	addDCDTEntryInVMOutput(vmOutput, []byte(core.DCDTModifyRoyalties), vmInput.Arguments[tokenIDIndex], dcdtInfo.dcdtData.TokenMetaData.Nonce, big.NewInt(0), extraTopics...)

	return vmOutput, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtModifyRoyalties) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTModifyRoyalties
	e.mutExecution.Unlock()
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *dcdtModifyRoyalties) IsInterfaceNil() bool {
	return e == nil
}
