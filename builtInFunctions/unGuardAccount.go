package builtInFunctions

import (
	"github.com/TerraDharitri/drt-go-core/core"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

type unGuardAccountFunc struct {
	*baseGuardAccount
}

// NewUnGuardAccountFunc will instantiate a new un-guard account built-in function
func NewUnGuardAccountFunc(args GuardAccountArgs) (*unGuardAccountFunc, error) {
	base, err := newBaseGuardAccount(args)
	if err != nil {
		return nil, err
	}
	return &unGuardAccountFunc{baseGuardAccount: base}, nil
}

// ProcessBuiltinFunction will unset the frozen bit in
// user's code metadata, if it has at least one enabled guardian
func (ua *unGuardAccountFunc) ProcessBuiltinFunction(
	acntSnd, _ vmcommon.UserAccountHandler,
	vmInput *vmcommon.ContractCallInput,
) (*vmcommon.VMOutput, error) {
	ua.mutExecution.Lock()
	defer ua.mutExecution.Unlock()

	err := ua.checkGuardAccountArgs(acntSnd, vmInput)
	if err != nil {
		return nil, err
	}

	err = unGuardAccount(acntSnd)
	if err != nil {
		return nil, err
	}

	entry := &vmcommon.LogEntry{
		Address:    acntSnd.AddressBytes(),
		Identifier: []byte(core.BuiltInFunctionUnGuardAccount),
	}

	return &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: vmInput.GasProvided - ua.funcGasCost,
		Logs:         []*vmcommon.LogEntry{entry},
	}, nil
}

func unGuardAccount(account vmcommon.UserAccountHandler) error {
	codeMetaData := getCodeMetaData(account)
	if !codeMetaData.Guarded {
		return ErrSetUnGuardAccount
	}

	codeMetaData.Guarded = false
	account.SetCodeMetadata(codeMetaData.ToBytes())
	return nil
}
