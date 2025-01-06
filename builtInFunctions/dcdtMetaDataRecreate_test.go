package builtInFunctions

import (
	"errors"
	"math/big"
	"testing"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
	"github.com/TerraDharitri/drt-go-vm-common/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewDCDTMetaDataRecreateFunc(t *testing.T) {
	t.Parallel()

	t.Run("nil accounts adapter", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, nil, nil, nil, nil, nil, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilAccountsAdapter, err)
	})
	t.Run("nil global settings handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, nil, nil, nil, nil, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilGlobalSettingsHandler, err)
	})
	t.Run("nil enable epochs handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, nil, nil, nil, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilEnableEpochsHandler, err)
	})
	t.Run("nil storage handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, nil, nil, &mock.EnableEpochsHandlerStub{}, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilDCDTNFTStorageHandler, err)
	})
	t.Run("nil roles handler", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, nil, &mock.EnableEpochsHandlerStub{}, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilRolesHandler, err)
	})
	t.Run("nil marshaller", func(t *testing.T) {
		t.Parallel()

		e, err := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, nil)
		assert.Nil(t, e)
		assert.Equal(t, ErrNilMarshalizer, err)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		funcGasCost := uint64(10)
		e, err := NewDCDTMetaDataRecreateFunc(funcGasCost, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		assert.NotNil(t, e)
		assert.Nil(t, err)
		assert.Equal(t, funcGasCost, e.funcGasCost)
	})
}

func TestDCDTMetaDataRecreate_ProcessBuiltinFunction(t *testing.T) {
	t.Parallel()

	t.Run("nil vmInput", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, nil)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrNilVmInput, err)
	})
	t.Run("nil CallValue", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue: nil,
			},
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrNilValue, err)
	})
	t.Run("call value not zero", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue: big.NewInt(10),
			},
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrBuiltInFunctionCalledWithValue, err)
	})
	t.Run("recipient address is not caller address", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
			},
			RecipientAddr: []byte("recipient"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrInvalidRcvAddr, err)
	})
	t.Run("nil sender account", func(t *testing.T) {
		t.Parallel()

		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(nil, nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrNilUserAccount, err)
	})
	t.Run("built-in function is not active", func(t *testing.T) {
		t.Parallel()

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return false
			},
		}
		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, enableEpochsHandler, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrBuiltInFunctionIsNotActive, err)
	})
	t.Run("invalid number of arguments", func(t *testing.T) {
		t.Parallel()

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, enableEpochsHandler, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
				Arguments:  [][]byte{},
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, ErrInvalidNumberOfArguments, err)
	})
	t.Run("check allowed to execute failed", func(t *testing.T) {
		t.Parallel()

		allowedToExecuteCalled := false
		expectedErr := errors.New("expected error")
		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		rolesHandler := &mock.DCDTRoleHandlerStub{
			CheckAllowedToExecuteCalled: func(account vmcommon.UserAccountHandler, tokenID []byte, role []byte) error {
				allowedToExecuteCalled = true
				return expectedErr
			},
		}
		e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, rolesHandler, enableEpochsHandler, &mock.MarshalizerMock{})
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  big.NewInt(0),
				CallerAddr: []byte("caller"),
				Arguments:  [][]byte{[]byte("tokenID"), {}, {}, {}, {}, {}, {}},
			},
			RecipientAddr: []byte("caller"),
		}
		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, vmOutput)
		assert.Equal(t, expectedErr, err)
		assert.True(t, allowedToExecuteCalled)
	})
	t.Run("recreate dynamic dcdt data", func(t *testing.T) {
		t.Parallel()

		getDCDTNFTTokenOnDestinationCalled := false
		saveDCDTNFTTokenCalled := false
		tokenId := []byte("tokenID")
		dcdtTokenKey := append([]byte(baseDCDTKeyPrefix), tokenId...)
		nonce := uint64(15)

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		globalSettingsHandler := &mock.GlobalSettingsHandlerStub{
			GetTokenTypeCalled: func(key []byte) (uint32, error) {
				assert.Equal(t, dcdtTokenKey, key)
				return uint32(core.DynamicNFT), nil
			},
		}
		accounts := &mock.AccountsStub{}
		newMetadata := &dcdt.MetaData{
			Nonce:      nonce,
			Name:       []byte("name"),
			Creator:    []byte("caller"),
			Royalties:  50,
			Hash:       []byte("hash"),
			URIs:       [][]byte{[]byte("uri1"), []byte("uri2")},
			Attributes: []byte("attributes"),
		}
		storageHandler := &mock.DCDTNFTStorageHandlerStub{
			GetDCDTNFTTokenOnDestinationCalled: func(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, bool, error) {
				getDCDTNFTTokenOnDestinationCalled = true
				return &dcdt.DCDigitalToken{
					Value:         big.NewInt(1),
					TokenMetaData: &dcdt.MetaData{Nonce: nonce},
				}, false, nil
			},
			SaveDCDTNFTTokenCalled: func(senderAddress []byte, acnt vmcommon.UserAccountHandler, tokenKey []byte, n uint64, dcdtData *dcdt.DCDigitalToken, properties vmcommon.NftSaveArgs) ([]byte, error) {
				assert.Equal(t, dcdtTokenKey, tokenKey)
				assert.Equal(t, nonce, n)
				assert.Equal(t, newMetadata, dcdtData.TokenMetaData)
				saveDCDTNFTTokenCalled = true
				return nil, nil
			},
		}
		e, _ := NewDCDTMetaDataRecreateFunc(101, vmcommon.BaseOperationCost{StorePerByte: 1}, accounts, globalSettingsHandler, storageHandler, &mock.DCDTRoleHandlerStub{}, enableEpochsHandler, &mock.MarshalizerMock{})

		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:   big.NewInt(0),
				CallerAddr:  []byte("caller"),
				GasProvided: 1000,
				Arguments:   [][]byte{tokenId, {15}, newMetadata.Name, {50}, newMetadata.Hash, newMetadata.Attributes, newMetadata.URIs[0], newMetadata.URIs[1]},
			},
			RecipientAddr: []byte("caller"),
		}

		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, err)
		assert.Equal(t, vmcommon.Ok, vmOutput.ReturnCode)
		assert.Equal(t, uint64(866), vmOutput.GasRemaining)
		assert.True(t, saveDCDTNFTTokenCalled)
		assert.True(t, getDCDTNFTTokenOnDestinationCalled)
	})

	t.Run("recreate non dynamic dcdt data", func(t *testing.T) {
		t.Parallel()

		getDCDTNFTTokenOnDestinationCalled := false
		saveDCDTNFTTokenCalled := false
		tokenId := []byte("tokenID")
		dcdtTokenKey := append([]byte(baseDCDTKeyPrefix), tokenId...)
		nonce := uint64(15)

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		globalSettingsHandler := &mock.GlobalSettingsHandlerStub{
			GetTokenTypeCalled: func(key []byte) (uint32, error) {
				assert.Equal(t, dcdtTokenKey, key)
				return uint32(core.NonFungible), nil
			},
		}
		accounts := &mock.AccountsStub{}
		newMetadata := &dcdt.MetaData{
			Nonce:      nonce,
			Name:       []byte("name"),
			Creator:    []byte("caller"),
			Royalties:  50,
			Hash:       []byte("hash"),
			URIs:       [][]byte{[]byte("uri1"), []byte("uri2")},
			Attributes: []byte("attributes"),
		}
		storageHandler := &mock.DCDTNFTStorageHandlerStub{
			GetDCDTNFTTokenOnDestinationCalled: func(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, bool, error) {
				getDCDTNFTTokenOnDestinationCalled = true
				return &dcdt.DCDigitalToken{
					Value:         big.NewInt(1),
					TokenMetaData: &dcdt.MetaData{Nonce: nonce},
				}, false, nil
			},
			SaveDCDTNFTTokenCalled: func(senderAddress []byte, acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64, dcdtData *dcdt.DCDigitalToken, properties vmcommon.NftSaveArgs) ([]byte, error) {
				assert.Equal(t, newMetadata, dcdtData.TokenMetaData)
				saveDCDTNFTTokenCalled = true
				return nil, nil
			},
		}
		e, _ := NewDCDTMetaDataRecreateFunc(101, vmcommon.BaseOperationCost{StorePerByte: 1}, accounts, globalSettingsHandler, storageHandler, &mock.DCDTRoleHandlerStub{}, enableEpochsHandler, &mock.MarshalizerMock{})

		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:   big.NewInt(0),
				CallerAddr:  []byte("caller"),
				GasProvided: 1000,
				Arguments:   [][]byte{tokenId, {15}, newMetadata.Name, {50}, newMetadata.Hash, newMetadata.Attributes, newMetadata.URIs[0], newMetadata.URIs[1]},
			},
			RecipientAddr: []byte("caller"),
		}

		vmOutput, err := e.ProcessBuiltinFunction(mock.NewUserAccount([]byte("addr")), nil, vmInput)
		assert.Nil(t, err)
		assert.Equal(t, vmcommon.Ok, vmOutput.ReturnCode)
		assert.Equal(t, uint64(866), vmOutput.GasRemaining)
		assert.True(t, saveDCDTNFTTokenCalled)
		assert.True(t, getDCDTNFTTokenOnDestinationCalled)
	})
}

func TestDcdtMetaDataRecreate_SetNewGasConfig(t *testing.T) {
	t.Parallel()

	e, _ := NewDCDTMetaDataRecreateFunc(0, vmcommon.BaseOperationCost{}, &mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.DCDTNFTStorageHandlerStub{}, &mock.DCDTRoleHandlerStub{}, &mock.EnableEpochsHandlerStub{}, &mock.MarshalizerMock{})

	newGasCost := &vmcommon.GasCost{
		BaseOperationCost: vmcommon.BaseOperationCost{
			StorePerByte: 15,
		},
		BuiltInCost: vmcommon.BuiltInCost{
			DCDTNFTRecreate: 10,
		},
	}
	e.SetNewGasConfig(newGasCost)

	assert.Equal(t, newGasCost.BuiltInCost.DCDTNFTRecreate, e.funcGasCost)
	assert.Equal(t, newGasCost.BaseOperationCost.StorePerByte, e.gasConfig.StorePerByte)
}

func TestDcdtMetaDataRecreate_changeDcdtVersion(t *testing.T) {
	t.Parallel()

	t.Run("flag disabled does nothing", func(t *testing.T) {
		t.Parallel()

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return false
			},
		}
		dcdtData := &dcdt.DCDigitalToken{}
		dcdtVersion := &dcdt.MetaDataVersion{
			URIs: 50,
		}

		err := changeDcdtVersion(dcdtData, dcdtVersion, enableEpochsHandler, &mock.MarshalizerMock{})
		assert.Nil(t, err)
		assert.Nil(t, dcdtData.Reserved)
	})
	t.Run("if flag is activated will change version", func(t *testing.T) {
		t.Parallel()

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				return true
			},
		}
		dcdtData := &dcdt.DCDigitalToken{
			Reserved: []byte{1},
			TokenMetaData: &dcdt.MetaData{
				Name: []byte("name"),
			},
		}
		dcdtVersion := &dcdt.MetaDataVersion{
			URIs: 50,
		}
		marshaller := &mock.MarshalizerMock{}
		dcdtVersionBytes, _ := marshaller.Marshal(dcdtVersion)

		err := changeDcdtVersion(dcdtData, dcdtVersion, enableEpochsHandler, marshaller)
		assert.Nil(t, err)
		assert.Equal(t, dcdtVersionBytes, dcdtData.Reserved)
	})
}

func TestGetDcdtInfo(t *testing.T) {
	t.Parallel()

	t.Run("dynamic metaDcdt not found will return empty struct with nonce set", func(t *testing.T) {
		t.Parallel()

		tokenId := []byte("tokenID")
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{tokenId, {2}},
			},
		}
		accnt := mock.NewUserAccount([]byte("addr"))
		storageHandler := &mock.DCDTNFTStorageHandlerStub{
			GetMetaDataFromSystemAccountCalled: func(bytes []byte, u uint64) (*dcdt.DCDigitalToken, error) {
				return nil, nil
			},
		}
		globalSettingsHandler := &mock.GlobalSettingsHandlerStub{
			GetTokenTypeCalled: func(dcdtTokenKey []byte) (uint32, error) {
				return uint32(core.DynamicMeta), nil
			},
		}

		dcdtInfo, err := getDcdtInfo(vmInput, accnt, storageHandler, globalSettingsHandler)
		assert.Nil(t, err)
		assert.NotNil(t, dcdtInfo)
		assert.NotNil(t, dcdtInfo.dcdtData)
		assert.Equal(t, uint64(2), dcdtInfo.dcdtData.TokenMetaData.Nonce)
		assert.True(t, dcdtInfo.metaDataInSystemAcc)
	})
	t.Run("dynamic sft not found will return empty struct with nonce set", func(t *testing.T) {
		t.Parallel()

		tokenId := []byte("tokenID")
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{tokenId, {2}},
			},
		}
		accnt := mock.NewUserAccount([]byte("addr"))
		storageHandler := &mock.DCDTNFTStorageHandlerStub{
			GetMetaDataFromSystemAccountCalled: func(bytes []byte, u uint64) (*dcdt.DCDigitalToken, error) {
				return nil, nil
			},
		}
		globalSettingsHandler := &mock.GlobalSettingsHandlerStub{
			GetTokenTypeCalled: func(dcdtTokenKey []byte) (uint32, error) {
				return uint32(core.DynamicSFT), nil
			},
		}

		dcdtInfo, err := getDcdtInfo(vmInput, accnt, storageHandler, globalSettingsHandler)
		assert.Nil(t, err)
		assert.NotNil(t, dcdtInfo)
		assert.NotNil(t, dcdtInfo.dcdtData)
		assert.Equal(t, uint64(2), dcdtInfo.dcdtData.TokenMetaData.Nonce)
		assert.True(t, dcdtInfo.metaDataInSystemAcc)
	})
	t.Run("dynamic nft not found will return empty struct with nonce set", func(t *testing.T) {
		t.Parallel()

		tokenId := []byte("tokenID")
		vmInput := &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				Arguments: [][]byte{tokenId, {2}},
			},
		}
		accnt := mock.NewUserAccount([]byte("addr"))
		storageHandler := &mock.DCDTNFTStorageHandlerStub{
			GetDCDTNFTTokenOnDestinationCalled: func(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, bool, error) {
				return &dcdt.DCDigitalToken{}, true, nil
			},
		}
		globalSettingsHandler := &mock.GlobalSettingsHandlerStub{
			GetTokenTypeCalled: func(dcdtTokenKey []byte) (uint32, error) {
				return uint32(core.DynamicNFT), nil
			},
		}

		dcdtInfo, err := getDcdtInfo(vmInput, accnt, storageHandler, globalSettingsHandler)
		assert.Nil(t, err)
		assert.NotNil(t, dcdtInfo)
		assert.NotNil(t, dcdtInfo.dcdtData)
		assert.Equal(t, uint64(2), dcdtInfo.dcdtData.TokenMetaData.Nonce)
		assert.False(t, dcdtInfo.metaDataInSystemAcc)
	})

}
