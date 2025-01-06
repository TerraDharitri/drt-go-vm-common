package builtInFunctions

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/core/check"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
	"github.com/TerraDharitri/drt-go-vm-common/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewDCDTGlobalSettingsFunc(t *testing.T) {
	t.Parallel()

	t.Run("nil accounts should error", func(t *testing.T) {
		t.Parallel()

		globalSettingsFunc, err := NewDCDTGlobalSettingsFunc(nil, &mock.MarshalizerMock{}, true, core.BuiltInFunctionDCDTPause, trueHandler)
		assert.Equal(t, ErrNilAccountsAdapter, err)
		assert.True(t, check.IfNil(globalSettingsFunc))
	})
	t.Run("nil marshaller should error", func(t *testing.T) {
		t.Parallel()

		globalSettingsFunc, err := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{}, nil, true, core.BuiltInFunctionDCDTPause, trueHandler)
		assert.Equal(t, ErrNilMarshalizer, err)
		assert.True(t, check.IfNil(globalSettingsFunc))
	})
	t.Run("nil active handler should error", func(t *testing.T) {
		t.Parallel()

		globalSettingsFunc, err := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{}, &mock.MarshalizerMock{}, true, core.BuiltInFunctionDCDTPause, nil)
		assert.Equal(t, ErrNilActiveHandler, err)
		assert.True(t, check.IfNil(globalSettingsFunc))
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		globalSettingsFunc, err := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{}, &mock.MarshalizerMock{}, true, core.BuiltInFunctionDCDTPause, falseHandler)
		assert.Nil(t, err)
		assert.False(t, check.IfNil(globalSettingsFunc))
	})
}

func TestDCDTGlobalSettingsPause_ProcessBuiltInFunction(t *testing.T) {
	t.Parallel()

	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, true, core.BuiltInFunctionDCDTPause, falseHandler)
	_, err := globalSettingsFunc.ProcessBuiltinFunction(nil, nil, nil)
	assert.Equal(t, err, ErrNilVmInput)

	input := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(0),
		},
	}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrInvalidArguments)

	input = &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			GasProvided: 50,
			CallValue:   big.NewInt(1),
		},
	}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrBuiltInFunctionCalledWithValue)

	input.CallValue = big.NewInt(0)
	key := []byte("key")
	value := []byte("value")
	input.Arguments = [][]byte{key, value}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrInvalidArguments)

	input.Arguments = [][]byte{key}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrAddressIsNotDCDTSystemSC)

	input.CallerAddr = core.DCDTSCAddress
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrOnlySystemAccountAccepted)

	input.RecipientAddr = vmcommon.SystemAccountAddress
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)

	pauseKey := []byte(baseDCDTKeyPrefix + string(key))
	assert.True(t, globalSettingsFunc.IsPaused(pauseKey))
	assert.False(t, globalSettingsFunc.IsLimitedTransfer(pauseKey))

	dcdtGlobalSettingsFalse, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, false, core.BuiltInFunctionDCDTUnPause, falseHandler)

	_, err = dcdtGlobalSettingsFalse.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)

	assert.False(t, globalSettingsFunc.IsPaused(pauseKey))
	assert.False(t, globalSettingsFunc.IsLimitedTransfer(pauseKey))
}

func TestDCDTGlobalSettingsPause_ProcessBuiltInFunctionGetNodeFromDbErr(t *testing.T) {
	t.Parallel()

	globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(
		&mock.AccountsStub{
			LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
				return &mock.AccountWrapMock{
					RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
						return nil, 0, core.NewGetNodeFromDBErrWithKey([]byte("key"), errors.New("error"), "")
					},
				}, nil
			},
		},
		&mock.MarshalizerMock{},
		true,
		core.BuiltInFunctionDCDTPause,
		falseHandler,
	)

	key := []byte("key")
	input := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			GasProvided: 50,
			CallValue:   big.NewInt(0),
			Arguments:   [][]byte{key},
			CallerAddr:  core.DCDTSCAddress,
		},
		RecipientAddr: vmcommon.SystemAccountAddress,
	}

	output, err := globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, output)
	assert.True(t, core.IsGetNodeFromDBError(err))
}

func TestDCDTGlobalSettingsLimitedTransfer_ProcessBuiltInFunction(t *testing.T) {
	t.Parallel()

	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, true, core.BuiltInFunctionDCDTSetLimitedTransfer, trueHandler)
	_, err := globalSettingsFunc.ProcessBuiltinFunction(nil, nil, nil)
	assert.Equal(t, err, ErrNilVmInput)

	input := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(0),
		},
	}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrInvalidArguments)

	input = &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			GasProvided: 50,
			CallValue:   big.NewInt(1),
		},
	}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrBuiltInFunctionCalledWithValue)

	input.CallValue = big.NewInt(0)
	key := []byte("key")
	value := []byte("value")
	input.Arguments = [][]byte{key, value}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrInvalidArguments)

	input.Arguments = [][]byte{key}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrAddressIsNotDCDTSystemSC)

	input.CallerAddr = core.DCDTSCAddress
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrOnlySystemAccountAccepted)

	input.RecipientAddr = vmcommon.SystemAccountAddress
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)

	tokenID := []byte(baseDCDTKeyPrefix + string(key))
	assert.False(t, globalSettingsFunc.IsPaused(tokenID))
	assert.True(t, globalSettingsFunc.IsLimitedTransfer(tokenID))

	pauseFunc, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, true, core.BuiltInFunctionDCDTPause, falseHandler)

	_, err = pauseFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)
	assert.True(t, globalSettingsFunc.IsPaused(tokenID))
	assert.True(t, globalSettingsFunc.IsLimitedTransfer(tokenID))

	dcdtGlobalSettingsFalse, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, false, core.BuiltInFunctionDCDTUnSetLimitedTransfer, trueHandler)

	_, err = dcdtGlobalSettingsFalse.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)

	assert.False(t, globalSettingsFunc.IsLimitedTransfer(tokenID))
}

func TestDCDTGlobalSettingsBurnForAll_ProcessBuiltInFunction(t *testing.T) {
	t.Parallel()

	acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, true, vmcommon.BuiltInFunctionDCDTSetBurnRoleForAll, falseHandler)
	_, err := globalSettingsFunc.ProcessBuiltinFunction(nil, nil, nil)
	assert.Equal(t, err, ErrNilVmInput)

	input := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallValue: big.NewInt(0),
		},
	}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrInvalidArguments)

	input = &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			GasProvided: 50,
			CallValue:   big.NewInt(1),
		},
	}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrBuiltInFunctionCalledWithValue)

	input.CallValue = big.NewInt(0)
	key := []byte("key")
	value := []byte("value")
	input.Arguments = [][]byte{key, value}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrInvalidArguments)

	input.Arguments = [][]byte{key}
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrAddressIsNotDCDTSystemSC)

	input.CallerAddr = core.DCDTSCAddress
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Equal(t, err, ErrOnlySystemAccountAccepted)

	input.RecipientAddr = vmcommon.SystemAccountAddress
	_, err = globalSettingsFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)

	tokenID := []byte(baseDCDTKeyPrefix + string(key))
	assert.False(t, globalSettingsFunc.IsPaused(tokenID))
	assert.False(t, globalSettingsFunc.IsLimitedTransfer(tokenID))
	assert.True(t, globalSettingsFunc.IsBurnForAll(tokenID))

	pauseFunc, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, true, core.BuiltInFunctionDCDTPause, falseHandler)

	_, err = pauseFunc.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)
	assert.True(t, globalSettingsFunc.IsPaused(tokenID))
	assert.False(t, globalSettingsFunc.IsLimitedTransfer(tokenID))
	assert.True(t, globalSettingsFunc.IsBurnForAll(tokenID))

	dcdtGlobalSettingsFalse, _ := NewDCDTGlobalSettingsFunc(&mock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return acnt, nil
		},
	}, &mock.MarshalizerMock{}, false, vmcommon.BuiltInFunctionDCDTUnSetBurnRoleForAll, falseHandler)

	_, err = dcdtGlobalSettingsFalse.ProcessBuiltinFunction(nil, nil, input)
	assert.Nil(t, err)

	assert.False(t, globalSettingsFunc.IsLimitedTransfer(tokenID))
}

func TestDcdtGlobalSettings_SetTokenType(t *testing.T) {
	t.Parallel()

	t.Run("invalid token type", func(t *testing.T) {
		t.Parallel()

		acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
		globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(
			&mock.AccountsStub{
				LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return acnt, nil
				},
			},
			&mock.MarshalizerMock{},
			true,
			core.BuiltInFunctionDCDTPause,
			falseHandler,
		)

		err := globalSettingsFunc.SetTokenType([]byte("key"), 100)
		require.True(t, strings.Contains(err.Error(), "invalid dcdt type"))
	})
	t.Run("fungible token type", func(t *testing.T) {
		t.Parallel()

		acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
		globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(
			&mock.AccountsStub{
				LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return acnt, nil
				},
			},
			&mock.MarshalizerMock{},
			true,
			core.BuiltInFunctionDCDTPause,
			falseHandler,
		)

		err := globalSettingsFunc.SetTokenType([]byte("key"), uint32(core.Fungible))
		require.Nil(t, err)
		retrievedVal := acnt.Storage["key"]
		require.Equal(t, []byte{0, 1}, retrievedVal)
	})
}

func TestDcdtGlobalSettings_GetTokenType(t *testing.T) {
	t.Parallel()

	t.Run("token type not set", func(t *testing.T) {
		t.Parallel()

		acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
		globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(
			&mock.AccountsStub{
				LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return acnt, nil
				},
			},
			&mock.MarshalizerMock{},
			true,
			core.BuiltInFunctionDCDTPause,
			falseHandler,
		)

		acnt.Storage["key"] = []byte{byte(notSet)}
		val, err := globalSettingsFunc.GetTokenType([]byte("key"))
		require.Nil(t, err)
		require.Equal(t, uint32(core.NonFungible), val)
	})
	t.Run("retrieve token type error", func(t *testing.T) {
		t.Parallel()

		acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
		globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(
			&mock.AccountsStub{
				LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return acnt, nil
				},
			},
			&mock.MarshalizerMock{},
			true,
			core.BuiltInFunctionDCDTPause,
			falseHandler,
		)

		acnt.Storage["key"] = []byte{0, 100}
		val, err := globalSettingsFunc.GetTokenType([]byte("key"))
		require.True(t, strings.Contains(err.Error(), "invalid dcdt type"))
		require.Equal(t, uint32(0), val)
	})
	t.Run("convert to dcdt token type", func(t *testing.T) {
		t.Parallel()

		acnt := mock.NewUserAccount(vmcommon.SystemAccountAddress)
		globalSettingsFunc, _ := NewDCDTGlobalSettingsFunc(
			&mock.AccountsStub{
				LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return acnt, nil
				},
			},
			&mock.MarshalizerMock{},
			true,
			core.BuiltInFunctionDCDTPause,
			falseHandler,
		)

		acnt.Storage["key"] = []byte{0, byte(fungible)}
		val, err := globalSettingsFunc.GetTokenType([]byte("key"))
		require.Nil(t, err)
		require.Equal(t, uint32(core.Fungible), val)
	})
}
