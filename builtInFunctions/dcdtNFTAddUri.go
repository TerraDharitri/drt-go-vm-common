package builtInFunctions

import (
	"math/big"
	"sync"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	"github.com/TerraDharitri/drt-go-core/marshal"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

type dcdtNFTAddUri struct {
	baseActiveHandler
	vmcommon.BlockchainDataProvider
	keyPrefix             []byte
	dcdtStorageHandler    vmcommon.DCDTNFTStorageHandler
	globalSettingsHandler vmcommon.DCDTGlobalSettingsHandler
	rolesHandler          vmcommon.DCDTRoleHandler
	gasConfig             vmcommon.BaseOperationCost
	enableEpochsHandler   vmcommon.EnableEpochsHandler
	funcGasCost           uint64
	marshaller            marshal.Marshalizer
	mutExecution          sync.RWMutex
}

// NewDCDTNFTAddUriFunc returns the dcdt NFT add URI built-in function component
func NewDCDTNFTAddUriFunc(
	funcGasCost uint64,
	gasConfig vmcommon.BaseOperationCost,
	dcdtStorageHandler vmcommon.DCDTNFTStorageHandler,
	globalSettingsHandler vmcommon.DCDTGlobalSettingsHandler,
	rolesHandler vmcommon.DCDTRoleHandler,
	enableEpochsHandler vmcommon.EnableEpochsHandler,
	marshaller marshal.Marshalizer,
) (*dcdtNFTAddUri, error) {
	if check.IfNil(dcdtStorageHandler) {
		return nil, ErrNilDCDTNFTStorageHandler
	}
	if check.IfNil(globalSettingsHandler) {
		return nil, ErrNilGlobalSettingsHandler
	}
	if check.IfNil(rolesHandler) {
		return nil, ErrNilRolesHandler
	}
	if check.IfNil(enableEpochsHandler) {
		return nil, ErrNilEnableEpochsHandler
	}
	if check.IfNil(marshaller) {
		return nil, ErrNilMarshalizer
	}

	e := &dcdtNFTAddUri{
		keyPrefix:              []byte(baseDCDTKeyPrefix),
		dcdtStorageHandler:     dcdtStorageHandler,
		funcGasCost:            funcGasCost,
		mutExecution:           sync.RWMutex{},
		globalSettingsHandler:  globalSettingsHandler,
		gasConfig:              gasConfig,
		rolesHandler:           rolesHandler,
		enableEpochsHandler:    enableEpochsHandler,
		BlockchainDataProvider: NewBlockchainDataProvider(),
		marshaller:             marshaller,
	}

	e.baseActiveHandler.activeHandler = func() bool {
		return enableEpochsHandler.IsFlagEnabled(DCDTNFTImprovementV1Flag)
	}

	return e, nil
}

// SetNewGasConfig is called whenever gas cost is changed
func (e *dcdtNFTAddUri) SetNewGasConfig(gasCost *vmcommon.GasCost) {
	if gasCost == nil {
		return
	}

	e.mutExecution.Lock()
	e.funcGasCost = gasCost.BuiltInCost.DCDTNFTAddURI
	e.gasConfig = gasCost.BaseOperationCost
	e.mutExecution.Unlock()
}

// ProcessBuiltinFunction resolves DCDT NFT add uris function call
// Requires 3 arguments:
// arg0 - token identifier
// arg1 - nonce
// arg[2:] - uris to add
func (e *dcdtNFTAddUri) ProcessBuiltinFunction(
	acntSnd, _ vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	e.mutExecution.RLock()
	defer e.mutExecution.RUnlock()

	err := checkDCDTNFTCreateBurnAddInput(acntSnd, vmInput, e.funcGasCost)
	if err != nil {
		return nil, err
	}
	if len(vmInput.Arguments) < 3 {
		return nil, ErrInvalidArguments
	}

	err = e.rolesHandler.CheckAllowedToExecute(acntSnd, vmInput.Arguments[0], []byte(core.DCDTRoleNFTAddURI))
	if err != nil {
		return nil, err
	}

	gasCostForStore := e.getGasCostForURIStore(vmInput)
	if vmInput.GasProvided < e.funcGasCost+gasCostForStore {
		return nil, ErrNotEnoughGas
	}

	dcdtTokenKey := append(e.keyPrefix, vmInput.Arguments[0]...)
	nonce := big.NewInt(0).SetBytes(vmInput.Arguments[1]).Uint64()
	if nonce == 0 {
		return nil, ErrNFTDoesNotHaveMetadata
	}
	dcdtData, err := e.dcdtStorageHandler.GetDCDTNFTTokenOnSender(acntSnd, dcdtTokenKey, nonce)
	if err != nil {
		return nil, err
	}

	metaDataVersion, _, err := getMetaDataVersion(dcdtData, e.enableEpochsHandler, e.marshaller)
	if err != nil {
		return nil, err
	}

	dcdtData.TokenMetaData.URIs = append(dcdtData.TokenMetaData.URIs, vmInput.Arguments[2:]...)
	metaDataVersion.URIs = e.CurrentRound()

	err = changeDcdtVersion(dcdtData, metaDataVersion, e.enableEpochsHandler, e.marshaller)
	if err != nil {
		return nil, err
	}

	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         true,
		IsReturnWithError:           vmInput.ReturnCallAfterError,
		KeepMetaDataOnZeroLiquidity: true,
	}
	_, err = e.dcdtStorageHandler.SaveDCDTNFTToken(acntSnd.AddressBytes(), acntSnd, dcdtTokenKey, nonce, dcdtData, properties)
	if err != nil {
		return nil, err
	}

	vmOutput := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: vmInput.GasProvided - e.funcGasCost - gasCostForStore,
	}

	extraTopics := append([][]byte{vmInput.CallerAddr}, vmInput.Arguments[2:]...)
	addDCDTEntryInVMOutput(vmOutput, []byte(core.BuiltInFunctionDCDTNFTAddURI), vmInput.Arguments[0], nonce, big.NewInt(0), extraTopics...)

	return vmOutput, nil
}

func (e *dcdtNFTAddUri) getGasCostForURIStore(vmInput *vmcommon.ContractCallInput) uint64 {
	lenURIs := 0
	for _, uri := range vmInput.Arguments[2:] {
		lenURIs += len(uri)
	}
	return uint64(lenURIs) * e.gasConfig.StorePerByte
}

// IsInterfaceNil returns true if underlying object in nil
func (e *dcdtNFTAddUri) IsInterfaceNil() bool {
	return e == nil
}
