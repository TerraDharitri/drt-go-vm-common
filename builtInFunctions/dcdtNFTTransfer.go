package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

const baseDCDTKeyPrefix = core.ProtectedKeyPrefix + core.DCDTKeyIdentifier

var oneValue = big.NewInt(1)
var zeroByteArray = []byte{0}

type dcdtNFTTransfer struct {
	baseAlwaysActiveHandler
	*baseComponentsHolder
	keyPrefix      []byte
	payableHandler vmcommon.PayableChecker
	funcGasCost    uint64
	accounts       vmcommon.AccountsAdapter
	gasConfig      vmcommon.BaseOperationCost
	mutExecution   sync.RWMutex
	rolesHandler   vmcommon.DCDTRoleHandler
}

// NewDCDTNFTTransferFunc returns the dcdt NFT transfer built-in function component
func NewDCDTNFTTransferFunc(
	funcGasCost uint64,
	marshaller vmcommon.Marshalizer,
	globalSettingsHandler vmcommon.GlobalMetadataHandler,
	accounts vmcommon.AccountsAdapter,
	shardCoordinator vmcommon.Coordinator,
	gasConfig vmcommon.BaseOperationCost,
	rolesHandler vmcommon.DCDTRoleHandler,
	dcdtStorageHandler vmcommon.DCDTNFTStorageHandler,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
) (*dcdtNFTTransfer, error) {
	if check.IfNil(marshaller) {
		return nil, ErrNilMarshalizer
	}
	if check.IfNil(globalSettingsHandler) {
		return nil, ErrNilGlobalSettingsHandler
	}
	if check.IfNil(accounts) {
		return nil, ErrNilAccountsAdapter
	}
	if check.IfNil(shardCoordinator) {
		return nil, ErrNilShardCoordinator
	}
	if check.IfNil(rolesHandler) {
		return nil, ErrNilRolesHandler
	}
	if check.IfNil(enableEpochsHandler) {
		return nil, ErrNilEnableEpochsHandler
	}
	if check.IfNil(dcdtStorageHandler) {
		return nil, ErrNilDCDTNFTStorageHandler
	}

	e := &dcdtNFTTransfer{
		keyPrefix:      []byte(baseDCDTKeyPrefix),
		funcGasCost:    funcGasCost,
		accounts:       accounts,
		gasConfig:      gasConfig,
		mutExecution:   sync.RWMutex{},
		payableHandler: &disabledPayableHandler{},
		rolesHandler:   rolesHandler,
		baseComponentsHolder: &baseComponentsHolder{
			dcdtStorageHandler:    dcdtStorageHandler,
			globalSettingsHandler: globalSettingsHandler,
			shardCoordinator:      shardCoordinator,
			enableEpochsHandler:   enableEpochsHandler,
			marshaller:            marshaller,
		},
	}

	return e, nil
}

// SetPayableChecker will set the payableCheck handler to the function
func (e *dcdtNFTTransfer) SetPayableChecker(payableHandler vmcommon.PayableChecker) error {
	if check.IfNil(payableHandler) {
		return ErrNilPayableHandler
	}

	e.payableHandler = payableHandler
	return nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtNFTTransfer) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTNFTTransfer
	e.gasConfig = gasCost.BaseOperationCost
	e.mutExecution.Unlock()
}

// ProcessBuiltinFunction resolves DCDT NFT transfer roles function call
// Requires 4 arguments:
// arg0 - token identifier
// arg1 - nonce
// arg2 - quantity to transfer
// arg3 - destination address
// if cross-shard, the rest of arguments will be filled inside the SCR
func (e *dcdtNFTTransfer) ProcessBuiltinFunction(
	acntSnd, acntDst vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	e.mutExecution.RLock()
	defer e.mutExecution.RUnlock()

	err := checkBasicDCDTArguments(vmInput)
	if err != nil {
		return nil, err
	}
	if len(vmInput.Arguments) < 4 {
		return nil, ErrInvalidArguments
	}

	if bytes.Equal(vmInput.CallerAddr, vmInput.RecipientAddr) {
		return e.processNFTTransferOnSenderShard(acntSnd, vmInput)
	}

	// in cross shard NFT transfer the sender account must be nil
	if !check.IfNil(acntSnd) {
		return nil, ErrInvalidRcvAddr
	}
	if check.IfNil(acntDst) {
		return nil, ErrInvalidRcvAddr
	}

	tickerID := vmInput.Arguments[0]
	dcdtTokenKey := append(e.keyPrefix, tickerID...)
	nonce := big.NewInt(0).SetBytes(vmInput.Arguments[1]).Uint64()
	value := big.NewInt(0).SetBytes(vmInput.Arguments[2])

	dcdtTransferData := &dcdt.DCDigitalToken{}
	if !bytes.Equal(vmInput.Arguments[3], zeroByteArray) {
		marshaledNFTTransfer := vmInput.Arguments[3]
		err = e.marshaller.Unmarshal(dcdtTransferData, marshaledNFTTransfer)
		if err != nil {
			return nil, err
		}
	} else {
		dcdtTransferData.Value = big.NewInt(0).Set(value)
		dcdtTransferData.Type = uint32(core.NonFungible)
	}

	err = e.payableHandler.CheckPayable(vmInput, vmInput.RecipientAddr, core.MinLenArgumentsDCDTNFTTransfer)
	if err != nil {
		return nil, err
	}
	err = e.addNFTToDestination(
		vmInput.CallerAddr,
		vmInput.RecipientAddr,
		acntDst,
		dcdtTransferData,
		dcdtTokenKey,
		nonce,
		vmInput.ReturnCallAfterError,
	)
	if err != nil {
		return nil, err
	}

	// no need to consume gas on destination - sender already paid for it
	vmOutput := &vmcommon.VMOutput{GasRemaining: vmInput.GasProvided}
	if len(vmInput.Arguments) > core.MinLenArgumentsDCDTNFTTransfer && vmcommon.IsSmartContractAddress(vmInput.RecipientAddr) {
		var callArgs [][]byte
		if len(vmInput.Arguments) > core.MinLenArgumentsDCDTNFTTransfer+1 {
			callArgs = vmInput.Arguments[core.MinLenArgumentsDCDTNFTTransfer+1:]
		}

		addOutputTransferToVMOutput(
			1,
			vmInput.CallerAddr,
			string(vmInput.Arguments[core.MinLenArgumentsDCDTNFTTransfer]),
			callArgs,
			vmInput.RecipientAddr,
			vmInput.GasLocked,
			vmInput.CallType,
			vmOutput)
	}

	addDCDTEntryForTransferInVMOutput(
		vmInput, vmOutput,
		[]byte(core.BuiltInFunctionDCDTNFTTransfer),
		acntDst.AddressBytes(),
		[]*TopicTokenData{{
			vmInput.Arguments[0],
			nonce,
			value,
		}},
	)

	return vmOutput, nil
}

func (e *dcdtNFTTransfer) processNFTTransferOnSenderShard(
	acntSnd vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	dstAddress := vmInput.Arguments[3]
	if len(dstAddress) != len(vmInput.CallerAddr) {
		return nil, fmt.Errorf("%w, not a valid destination address", ErrInvalidArguments)
	}
	if bytes.Equal(dstAddress, vmInput.CallerAddr) {
		return nil, fmt.Errorf("%w, can not transfer to self", ErrInvalidArguments)
	}
	isTransferToMeta := e.shardCoordinator.ComputeId(dstAddress) == core.MetachainShardId
	if isTransferToMeta {
		return nil, ErrInvalidRcvAddr
	}
	skipGasUse := noGasUseIfReturnCallAfterErrorWithFlag(e.enableEpochsHandler, vmInput)
	if vmInput.GasProvided < e.funcGasCost && !skipGasUse {
		return nil, ErrNotEnoughGas
	}

	tickerID := vmInput.Arguments[0]
	dcdtTokenKey := append(e.keyPrefix, tickerID...)
	nonce := big.NewInt(0).SetBytes(vmInput.Arguments[1]).Uint64()
	dcdtData, err := e.dcdtStorageHandler.GetDCDTNFTTokenOnSender(acntSnd, dcdtTokenKey, nonce)
	if err != nil {
		return nil, err
	}
	if nonce == 0 {
		return nil, ErrNFTDoesNotHaveMetadata
	}

	if len(vmInput.Arguments[2]) > core.MaxLenForDCDTIssueMint && e.enableEpochsHandler.IsFlagEnabled(ConsistentTokensValuesLengthCheckFlag) {
		return nil, fmt.Errorf("%w: max length for a transfer value is %d", ErrInvalidArguments, core.MaxLenForDCDTIssueMint)
	}
	quantityToTransfer := big.NewInt(0).SetBytes(vmInput.Arguments[2])
	if dcdtData.Value.Cmp(quantityToTransfer) < 0 {
		return nil, ErrInvalidNFTQuantity
	}

	isCheckTransferFlagEnabled := e.enableEpochsHandler.IsFlagEnabled(CheckTransferFlag)
	if isCheckTransferFlagEnabled && quantityToTransfer.Cmp(zero) <= 0 {
		return nil, ErrInvalidNFTQuantity
	}
	dcdtData.Value.Sub(dcdtData.Value, quantityToTransfer)

	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         false,
		IsReturnWithError:           vmInput.ReturnCallAfterError,
		KeepMetaDataOnZeroLiquidity: false,
	}
	_, err = e.dcdtStorageHandler.SaveDCDTNFTToken(acntSnd.AddressBytes(), acntSnd, dcdtTokenKey, nonce, dcdtData, properties)
	if err != nil {
		return nil, err
	}

	dcdtData.Value.Set(quantityToTransfer)

	var userAccount vmcommon.UserAccountHandler
	if e.shardCoordinator.SelfId() == e.shardCoordinator.ComputeId(dstAddress) {
		accountHandler, errLoad := e.accounts.LoadAccount(dstAddress)
		if errLoad != nil {
			return nil, errLoad
		}

		var ok bool
		userAccount, ok = accountHandler.(vmcommon.UserAccountHandler)
		if !ok {
			return nil, ErrWrongTypeAssertion
		}

		err = e.payableHandler.CheckPayable(vmInput, dstAddress, core.MinLenArgumentsDCDTNFTTransfer)
		if err != nil {
			return nil, err
		}
		err = e.addNFTToDestination(
			vmInput.CallerAddr,
			dstAddress,
			userAccount,
			dcdtData,
			dcdtTokenKey,
			nonce,
			vmInput.ReturnCallAfterError,
		)
		if err != nil {
			return nil, err
		}

		err = e.accounts.SaveAccount(userAccount)
		if err != nil {
			return nil, err
		}
	} else {
		keepMetadataOnZeroLiquidity, err := shouldKeepMetaDataOnZeroLiquidity(acntSnd, tickerID, dcdtData.Type, e.marshaller, e.enableEpochsHandler)
		if err != nil {
			return nil, err
		}

		err = e.dcdtStorageHandler.AddToLiquiditySystemAcc(dcdtTokenKey, dcdtData.Type, nonce, big.NewInt(0).Neg(quantityToTransfer), keepMetadataOnZeroLiquidity)
		if err != nil {
			return nil, err
		}
	}

	tokenID := dcdtTokenKey
	if e.enableEpochsHandler.IsFlagEnabled(CheckCorrectTokenIDForTransferRoleFlag) {
		tokenID = tickerID
	}

	err = checkIfTransferCanHappenWithLimitedTransfer(tokenID, dcdtTokenKey, acntSnd.AddressBytes(), dstAddress, e.globalSettingsHandler, e.rolesHandler, acntSnd, userAccount, vmInput.ReturnCallAfterError)
	if err != nil {
		return nil, err
	}

	vmOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: computeGasRemainingIfNeeded(acntSnd, vmInput.GasProvided, e.funcGasCost, skipGasUse),
	}
	err = e.createNFTOutputTransfers(vmInput, vmOutput, dcdtData, dstAddress, tickerID, nonce, skipGasUse)
	if err != nil {
		return nil, err
	}

	addDCDTEntryForTransferInVMOutput(
		vmInput, vmOutput,
		[]byte(core.BuiltInFunctionDCDTNFTTransfer),
		dstAddress,
		[]*TopicTokenData{{
			vmInput.Arguments[0],
			nonce,
			quantityToTransfer,
		}},
	)

	return vmOutput, nil
}

func shouldKeepMetaDataOnZeroLiquidity(
	acct vmcommon.UserAccountHandler,
	tickerId []byte,
	dcdtDataType uint32,
	marshaller vmcommon.Marshalizer,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
) (bool, error) {
	if dcdtDataType == uint32(core.DynamicSFT) || dcdtDataType == uint32(core.DynamicMeta) {
		return true, nil
	}

	hasDynamicRole, err := hasDynamicRole(acct, tickerId, marshaller, enableEpochsHandler)
	if err != nil {
		return false, err
	}
	return hasDynamicRole, nil
}

func hasDynamicRole(account vmcommon.UserAccountHandler, tokenID []byte, marshaller vmcommon.Marshalizer, enableEpochsHandler vmcommon.EnableEpochsHandler) (bool, error) {
	roleKey := append(roleKeyPrefix, tokenID...)
	roles, _, err := getDCDTRolesForAcnt(marshaller, account, roleKey)
	if err != nil {
		return false, err
	}

	dynamicRoles := [][]byte{
		[]byte(core.DCDTMetaDataRecreate),
		[]byte(core.DCDTRoleNFTUpdate),
		[]byte(core.DCDTRoleModifyCreator),
		[]byte(core.DCDTRoleModifyRoyalties),
		[]byte(core.DCDTRoleSetNewURI),
	}

	if enableEpochsHandler.IsFlagEnabled(DynamicDcdtFlag) {
		dynamicRoles = append(dynamicRoles, []byte(core.DCDTRoleNFTAddURI), []byte(core.DCDTRoleNFTUpdateAttributes))
	}

	for _, role := range dynamicRoles {
		_, exists := doesRoleExist(roles, role)
		if exists {
			return true, nil
		}
	}

	return false, nil
}

func (e *dcdtNFTTransfer) createNFTOutputTransfers(
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
	dcdtTransferData *dcdt.DCDigitalToken,
	dstAddress []byte,
	tickerID []byte,
	nonce uint64,
	noGasUse bool,
) error {
	nftTransferCallArgs := make([][]byte, 0)
	nftTransferCallArgs = append(nftTransferCallArgs, vmInput.Arguments[:3]...)

	wasAlreadySent, err := e.dcdtStorageHandler.WasAlreadySentToDestinationShardAndUpdateState(tickerID, nonce, dstAddress)
	if err != nil {
		return err
	}

	if !wasAlreadySent || dcdtTransferData.Value.Cmp(oneValue) == 0 {
		marshaledNFTTransfer, err := e.marshaller.Marshal(dcdtTransferData)
		if err != nil {
			return err
		}

		if !noGasUse {
			gasForTransfer := uint64(len(marshaledNFTTransfer)) * e.gasConfig.DataCopyPerByte
			if gasForTransfer > vmOutput.GasRemaining {
				return ErrNotEnoughGas
			}
			vmOutput.GasRemaining -= gasForTransfer
		}

		nftTransferCallArgs = append(nftTransferCallArgs, marshaledNFTTransfer)
	} else {
		nftTransferCallArgs = append(nftTransferCallArgs, zeroByteArray)
	}

	if len(vmInput.Arguments) > core.MinLenArgumentsDCDTNFTTransfer {
		nftTransferCallArgs = append(nftTransferCallArgs, vmInput.Arguments[4:]...)
	}

	isSCCallAfter := e.payableHandler.DetermineIsSCCallAfter(vmInput, dstAddress, core.MinLenArgumentsDCDTNFTTransfer)

	if e.shardCoordinator.SelfId() != e.shardCoordinator.ComputeId(dstAddress) {
		gasToTransfer := uint64(0)
		if isSCCallAfter {
			gasToTransfer = vmOutput.GasRemaining
			vmOutput.GasRemaining = 0
		}
		addNFTTransferToVMOutput(
			1,
			dstAddress,
			core.BuiltInFunctionDCDTNFTTransfer,
			nftTransferCallArgs,
			gasToTransfer,
			vmInput,
			vmOutput,
		)

		return nil
	}

	if isSCCallAfter {
		var callArgs [][]byte
		if len(vmInput.Arguments) > core.MinLenArgumentsDCDTNFTTransfer+1 {
			callArgs = vmInput.Arguments[core.MinLenArgumentsDCDTNFTTransfer+1:]
		}

		addOutputTransferToVMOutput(
			1,
			vmInput.CallerAddr,
			string(vmInput.Arguments[core.MinLenArgumentsDCDTNFTTransfer]),
			callArgs,
			dstAddress,
			vmInput.GasLocked,
			vmInput.CallType,
			vmOutput)
	}

	return nil
}

func addNFTTransferToVMOutput(
	index uint32,
	recipient []byte,
	funcToCall string,
	arguments [][]byte,
	gasLimit uint64,
	vmInput *vmcommon.ContractCallInput,
	vmOutput *vmcommon.VMOutput,
) {
	nftTransferTxData := funcToCall
	for _, arg := range arguments {
		nftTransferTxData += "@" + hex.EncodeToString(arg)
	}
	outTransfer := vmcommon.OutputTransfer{
		Index:         index,
		Value:         big.NewInt(0).Set(vmInput.CallValue),
		GasLimit:      gasLimit,
		GasLocked:     vmInput.GasLocked,
		Data:          []byte(nftTransferTxData),
		CallType:      vmInput.CallType,
		SenderAddress: vmInput.CallerAddr,
	}
	vmOutput.OutputAccounts = make(map[string]*vmcommon.OutputAccount)
	vmOutput.OutputAccounts[string(recipient)] = &vmcommon.OutputAccount{
		Address:         recipient,
		OutputTransfers: []vmcommon.OutputTransfer{outTransfer},
	}
}

// IsInterfaceNil returns true if underlying object in nil
func (e *dcdtNFTTransfer) IsInterfaceNil() bool {
	return e == nil
}
