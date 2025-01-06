package builtInFunctions

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/data/dcdt"
	"github.com/TerraDharitri/drt-go-core/marshal"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

const (
	nameIndex       = 2
	royaltiesIndex  = 3
	hashIndex       = 4
	attributesIndex = 5
	urisStartIndex  = 6
)

type dcdtMetaDataRecreate struct {
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

// NewDCDTMetaDataRecreateFunc returns the dcdt meta data recreate built-in function component
func NewDCDTMetaDataRecreateFunc(
	funcGasCost uint64,
	gasConfig vmcommon.BaseOperationCost,
	accounts vmcommon.AccountsAdapter,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	storageHandler vmcommon.DCDTNFTStorageHandler,
	rolesHandler vmcommon.DCDTRoleHandler,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) (*dcdtMetaDataRecreate, error) {
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

	e := &dcdtMetaDataRecreate{
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

func checkUpdateArguments(
	vmInput *vmcommon.ContractCallInput,
	acntSnd vmcommon.UserAccountHandler,
	handler baseActiveHandler,
	minNumOfArgs int,
	rolesHandler vmcommon.DCDTRoleHandler,
	role string,
) error {
	if vmInput == nil {
		return ErrNilVmInput
	}
	if vmInput.CallValue == nil {
		return ErrNilValue
	}
	if vmInput.CallValue.Cmp(zero) != 0 {
		return ErrBuiltInFunctionCalledWithValue
	}
	if !bytes.Equal(vmInput.CallerAddr, vmInput.RecipientAddr) {
		return ErrInvalidRcvAddr
	}
	if check.IfNil(acntSnd) {
		return ErrNilUserAccount
	}
	if !handler.IsActive() {
		return ErrBuiltInFunctionIsNotActive
	}
	if len(vmInput.Arguments) < minNumOfArgs {
		return ErrInvalidNumberOfArguments
	}
	if minNumOfArgs < 1 {
		return ErrInvalidNumberOfArguments
	}

	return rolesHandler.CheckAllowedToExecute(acntSnd, vmInput.Arguments[tokenIDIndex], []byte(role))
}

type dcdtStorageInfo struct {
	dcdtData            *dcdt.DCDigitalToken
	dcdtTokenKey        []byte
	nonce               uint64
	metaDataInSystemAcc bool
}

func getDcdtInfo(
	vmInput *vmcommon.ContractCallInput,
	acntSnd vmcommon.UserAccountHandler,
	storageHandler vmcommon.DCDTNFTStorageHandler,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
) (*dcdtStorageInfo, error) {
	dcdtTokenKey := append([]byte(baseDCDTKeyPrefix), vmInput.Arguments[tokenIDIndex]...)
	nonce := big.NewInt(0).SetBytes(vmInput.Arguments[nonceIndex]).Uint64()

	tokenType, err := globalSettingsHandler.GetTokenType(dcdtTokenKey)
	if err != nil {
		return nil, err
	}
	if tokenType == uint32(core.DynamicSFT) || tokenType == uint32(core.DynamicMeta) {
		dcdtData, err := storageHandler.GetMetaDataFromSystemAccount(dcdtTokenKey, nonce)
		if err != nil {
			return nil, err
		}

		if dcdtData == nil {
			dcdtData = &dcdt.DCDigitalToken{}
		}
		if dcdtData.TokenMetaData == nil {
			dcdtData.TokenMetaData = &dcdt.MetaData{
				Nonce: nonce,
			}
		}

		return &dcdtStorageInfo{
			dcdtData:            dcdtData,
			dcdtTokenKey:        dcdtTokenKey,
			nonce:               nonce,
			metaDataInSystemAcc: true,
		}, nil
	}

	dcdtData, isNew, err := storageHandler.GetDCDTNFTTokenOnDestination(acntSnd, dcdtTokenKey, nonce)
	if err != nil {
		return nil, err
	}

	if tokenType == uint32(core.DynamicNFT) {
		if isNew {
			dcdtData.TokenMetaData = &dcdt.MetaData{
				Nonce: nonce,
			}
			dcdtData.Type = tokenType
		}
		return &dcdtStorageInfo{
			dcdtData:            dcdtData,
			dcdtTokenKey:        dcdtTokenKey,
			nonce:               nonce,
			metaDataInSystemAcc: false,
		}, nil
	}

	if isNew {
		return nil, ErrNilDCDTData
	}

	if dcdtData.Value == nil || dcdtData.Value.Cmp(zero) == 0 {
		return nil, ErrInvalidDcdtValue
	}

	if dcdtData.TokenMetaData == nil {
		dcdtData.TokenMetaData = &dcdt.MetaData{
			Nonce: nonce,
		}
	}

	return &dcdtStorageInfo{
		dcdtData:            dcdtData,
		dcdtTokenKey:        dcdtTokenKey,
		nonce:               nonce,
		metaDataInSystemAcc: false,
	}, nil
}

func saveDCDTMetaDataInfo(
	dcdtInfo *dcdtStorageInfo,
	storageHandler vmcommon.DCDTNFTStorageHandler,
	acntSnd vmcommon.UserAccountHandler,
	returnCallAfterError bool,
) error {
	if dcdtInfo.metaDataInSystemAcc {
		return storageHandler.SaveMetaDataToSystemAccount(dcdtInfo.dcdtTokenKey, dcdtInfo.nonce, dcdtInfo.dcdtData)
	}

	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         true,
		IsReturnWithError:           returnCallAfterError,
		KeepMetaDataOnZeroLiquidity: true,
	}

	_, err := storageHandler.SaveDCDTNFTToken(acntSnd.AddressBytes(), acntSnd, dcdtInfo.dcdtTokenKey, dcdtInfo.nonce, dcdtInfo.dcdtData, properties)
	return err
}

func lenArgs(args [][]byte) int {
	totalLength := 0
	for _, arg := range args {
		totalLength += len(arg)
	}
	return totalLength
}

// ProcessBuiltinFunction saves the token type in the system account
func (e *dcdtMetaDataRecreate) ProcessBuiltinFunction(acntSnd, _ vmcommon.UserAccountHandler, vmInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	err := checkUpdateArguments(vmInput, acntSnd, e.baseActiveHandler, 7, e.rolesHandler, core.DCDTRoleNFTRecreate)
	if err != nil {
		return nil, err
	}

	totalLengthDifference := lenArgs(vmInput.Arguments)

	dcdtInfo, err := getDcdtInfo(vmInput, acntSnd, e.storageHandler, e.globalSettingsHandler)
	if err != nil {
		return nil, err
	}

	totalLengthDifference -= dcdtInfo.dcdtData.TokenMetaData.Size()
	if totalLengthDifference < 0 {
		totalLengthDifference = 0
	}

	e.mutExecution.RLock()
	gasToUse := uint64(totalLengthDifference)*e.gasConfig.StorePerByte + e.funcGasCost
	e.mutExecution.RUnlock()
	if vmInput.GasProvided < gasToUse {
		return nil, ErrNotEnoughGas
	}

	royalties := uint32(big.NewInt(0).SetBytes(vmInput.Arguments[royaltiesIndex]).Uint64())
	if royalties > core.MaxRoyalty {
		return nil, fmt.Errorf("%w, invalid max royality value", ErrInvalidArguments)
	}

	dcdtInfo.dcdtData.TokenMetaData.Name = vmInput.Arguments[nameIndex]
	dcdtInfo.dcdtData.TokenMetaData.Creator = vmInput.CallerAddr
	dcdtInfo.dcdtData.TokenMetaData.Royalties = royalties
	dcdtInfo.dcdtData.TokenMetaData.Hash = vmInput.Arguments[hashIndex]
	dcdtInfo.dcdtData.TokenMetaData.Attributes = vmInput.Arguments[attributesIndex]
	dcdtInfo.dcdtData.TokenMetaData.URIs = vmInput.Arguments[urisStartIndex:]

	currentRound := e.CurrentRound()
	metaDataVersion := &dcdt.MetaDataVersion{
		Name:       currentRound,
		Creator:    currentRound,
		Royalties:  currentRound,
		Hash:       currentRound,
		URIs:       currentRound,
		Attributes: currentRound,
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
		log.Warn("dcdtMetaDataRecreate.ProcessBuiltinFunction: cannot marshall dcdt data for log", "error", err)
	}

	addDCDTEntryInVMOutput(vmOutput, []byte(core.DCDTMetaDataRecreate), vmInput.Arguments[0], dcdtInfo.dcdtData.TokenMetaData.Nonce, big.NewInt(0), vmInput.CallerAddr, dcdtDataBytes)

	return vmOutput, nil
}

func changeDcdtVersion(
	dcdt *dcdt.DCDigitalToken,
	dcdtVersion *dcdt.MetaDataVersion,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) error {
	if !enableEpochsHandler.IsFlagEnabled(DynamicDcdtFlag) {
		return nil
	}

	dcdtVersionBytes, err := marshaller.Marshal(dcdtVersion)
	if err != nil {
		return err
	}

	dcdt.Reserved = dcdtVersionBytes
	return nil
}

func getMetaDataVersion(
	dcdtData *dcdt.DCDigitalToken,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) (*dcdt.MetaDataVersion, bool, error) {
	if !enableEpochsHandler.IsFlagEnabled(DynamicDcdtFlag) {
		return &dcdt.MetaDataVersion{}, false, nil
	}

	if !wasMetaDataUpdated(dcdtData.Reserved) {
		return &dcdt.MetaDataVersion{}, false, nil
	}

	dcdtMetaDataVersion := &dcdt.MetaDataVersion{}
	err := marshaller.Unmarshal(dcdtMetaDataVersion, dcdtData.Reserved)
	if err != nil {
		return nil, false, err
	}

	return dcdtMetaDataVersion, true, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtMetaDataRecreate) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTNFTRecreate
	e.gasConfig = gasCost.BaseOperationCost
	e.mutExecution.Unlock()
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *dcdtMetaDataRecreate) IsInterfaceNil() bool {
	return e == nil
}
