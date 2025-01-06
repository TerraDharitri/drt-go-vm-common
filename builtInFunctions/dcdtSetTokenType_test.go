package builtInFunctions

import (
	"math/big"
	"testing"

	"github.com/TerraDharitri/drt-go-core/core"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
	"github.com/TerraDharitri/drt-go-vm-common/mock"
	"github.com/stretchr/testify/require"
)

func TestNewDCDTSetTokenTypeFunc(t *testing.T) {
	t.Parallel()

	t.Run("nil accounts adapter", func(t *testing.T) {
		t.Parallel()

		_, err := NewDCDTSetTokenTypeFunc(nil, nil, nil, nil)
		require.Equal(t, ErrNilAccountsAdapter, err)
	})
	t.Run("nil marshaller", func(t *testing.T) {
		t.Parallel()

		_, err := NewDCDTSetTokenTypeFunc(&mock.AccountsStub{}, nil, nil, nil)
		require.Equal(t, ErrNilMarshalizer, err)
	})
	t.Run("nil global settings handler", func(t *testing.T) {
		t.Parallel()

		_, err := NewDCDTSetTokenTypeFunc(&mock.AccountsStub{}, nil, &mock.MarshalizerMock{}, nil)
		require.Equal(t, ErrNilGlobalSettingsHandler, err)
	})
	t.Run("nil active handler", func(t *testing.T) {
		t.Parallel()

		_, err := NewDCDTSetTokenTypeFunc(&mock.AccountsStub{}, &mock.GlobalSettingsHandlerStub{}, &mock.MarshalizerMock{}, nil)
		require.Equal(t, ErrNilActiveHandler, err)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		_, err := NewDCDTSetTokenTypeFunc(
			&mock.AccountsStub{},
			&mock.GlobalSettingsHandlerStub{},
			&mock.MarshalizerMock{},
			func() bool {
				return true
			},
		)
		require.Nil(t, err)
	})

}

func TestDCDTSetTokenType_ProcessBuiltinFunction(t *testing.T) {
	t.Parallel()

	t.Run("nil vm input", func(t *testing.T) {
		t.Parallel()

		e := &dcdtSetTokenType{}
		_, err := e.ProcessBuiltinFunction(nil, nil, nil)
		require.Equal(t, ErrNilVmInput, err)
	})
	t.Run("built-in function called with value", func(t *testing.T) {
		t.Parallel()

		e := &dcdtSetTokenType{}
		_, err := e.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue: big.NewInt(10),
			},
		})
		require.Equal(t, ErrBuiltInFunctionCalledWithValue, err)
	})
	t.Run("invalid arguments", func(t *testing.T) {
		t.Parallel()

		e := &dcdtSetTokenType{}
		_, err := e.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue: zero,
				Arguments: [][]byte{{}},
			},
		})
		require.Equal(t, ErrInvalidArguments, err)
	})
	t.Run("caller address is not DCDT system SC", func(t *testing.T) {
		t.Parallel()

		e := &dcdtSetTokenType{}
		_, err := e.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  zero,
				Arguments:  [][]byte{{}, {}},
				CallerAddr: []byte("random address"),
			},
		})
		require.Equal(t, ErrAddressIsNotDCDTSystemSC, err)
	})
	t.Run("recipient addr is not system account", func(t *testing.T) {
		t.Parallel()

		e := &dcdtSetTokenType{}
		_, err := e.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  zero,
				Arguments:  [][]byte{{}, {}},
				CallerAddr: core.DCDTSCAddress,
			},
			RecipientAddr: []byte("random address"),
		})
		require.Equal(t, ErrOnlySystemAccountAccepted, err)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		tokenKey := []byte("tokenKey")
		tokenType := []byte(core.NonFungibleDCDTv2)
		setTokenTypeCalled := false
		e := &dcdtSetTokenType{
			globalSettingsHandler: &mock.GlobalSettingsHandlerStub{
				SetTokenTypeCalled: func(dcdtTokenKey []byte, tokenType uint32) error {
					require.Equal(t, append([]byte(baseDCDTKeyPrefix), tokenKey...), dcdtTokenKey)
					require.Equal(t, uint32(core.NonFungibleV2), tokenType)
					setTokenTypeCalled = true
					return nil
				},
			},
		}

		_, err := e.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput: vmcommon.VMInput{
				CallValue:  zero,
				Arguments:  [][]byte{tokenKey, tokenType},
				CallerAddr: core.DCDTSCAddress,
			},
			RecipientAddr: core.SystemAccountAddress,
		})
		require.Nil(t, err)
		require.True(t, setTokenTypeCalled)
	})
}
