package mock

import (
	"math/big"

	"github.com/TerraDharitri/drt-go-core/data"
	"github.com/TerraDharitri/drt-go-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

// DCDTNFTStorageHandlerStub -
type DCDTNFTStorageHandlerStub struct {
	SaveDCDTNFTTokenCalled                                    func(senderAddress []byte, acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64, dcdtData *dcdt.DCDigitalToken, saveArgs vmcommon.NftSaveArgs) ([]byte, error)
	GetDCDTNFTTokenOnSenderCalled                             func(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, error)
	GetDCDTNFTTokenOnDestinationCalled                        func(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, bool, error)
	GetDCDTNFTTokenOnDestinationWithCustomSystemAccountCalled func(accnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64, systemAccount vmcommon.UserAccountHandler) (*dcdt.DCDigitalToken, bool, error)
	WasAlreadySentToDestinationShardAndUpdateStateCalled      func(tickerID []byte, nonce uint64, dstAddress []byte) (bool, error)
	SaveNFTMetaDataCalled                                     func(tx data.TransactionHandler) error
	AddToLiquiditySystemAccCalled                             func(dcdtTokenKey []byte, tokenType uint32, nonce uint64, transferValue *big.Int, keepMetadataOnZeroLiquidity bool) error
	GetMetaDataFromSystemAccountCalled                        func([]byte, uint64) (*dcdt.DCDigitalToken, error)
	SaveMetaDataToSystemAccountCalled                         func(tokenKey []byte, nonce uint64, dcdtData *dcdt.DCDigitalToken) error
}

// SaveDCDTNFTToken -
func (stub *DCDTNFTStorageHandlerStub) SaveDCDTNFTToken(senderAddress []byte, acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64, dcdtData *dcdt.DCDigitalToken, saveArgs vmcommon.NftSaveArgs) ([]byte, error) {
	if stub.SaveDCDTNFTTokenCalled != nil {
		return stub.SaveDCDTNFTTokenCalled(senderAddress, acnt, dcdtTokenKey, nonce, dcdtData, saveArgs)
	}
	return nil, nil
}

// GetDCDTNFTTokenOnSender -
func (stub *DCDTNFTStorageHandlerStub) GetDCDTNFTTokenOnSender(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, error) {
	if stub.GetDCDTNFTTokenOnSenderCalled != nil {
		return stub.GetDCDTNFTTokenOnSenderCalled(acnt, dcdtTokenKey, nonce)
	}
	return nil, nil
}

// GetMetaDataFromSystemAccount -
func (stub *DCDTNFTStorageHandlerStub) GetMetaDataFromSystemAccount(key []byte, nonce uint64) (*dcdt.DCDigitalToken, error) {
	if stub.GetMetaDataFromSystemAccountCalled != nil {
		return stub.GetMetaDataFromSystemAccountCalled(key, nonce)
	}
	return nil, nil
}

// SaveMetaDataToSystemAccount -
func (stub *DCDTNFTStorageHandlerStub) SaveMetaDataToSystemAccount(tokenKey []byte, nonce uint64, dcdtData *dcdt.DCDigitalToken) error {
	if stub.SaveMetaDataToSystemAccountCalled != nil {
		return stub.SaveMetaDataToSystemAccountCalled(tokenKey, nonce, dcdtData)
	}
	return nil
}

// GetDCDTNFTTokenOnDestination -
func (stub *DCDTNFTStorageHandlerStub) GetDCDTNFTTokenOnDestination(acnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64) (*dcdt.DCDigitalToken, bool, error) {
	if stub.GetDCDTNFTTokenOnDestinationCalled != nil {
		return stub.GetDCDTNFTTokenOnDestinationCalled(acnt, dcdtTokenKey, nonce)
	}
	return nil, false, nil
}

// GetDCDTNFTTokenOnDestinationWithCustomSystemAccount -
func (stub *DCDTNFTStorageHandlerStub) GetDCDTNFTTokenOnDestinationWithCustomSystemAccount(accnt vmcommon.UserAccountHandler, dcdtTokenKey []byte, nonce uint64, systemAccount vmcommon.UserAccountHandler) (*dcdt.DCDigitalToken, bool, error) {
	if stub.GetDCDTNFTTokenOnDestinationWithCustomSystemAccountCalled != nil {
		return stub.GetDCDTNFTTokenOnDestinationWithCustomSystemAccountCalled(accnt, dcdtTokenKey, nonce, systemAccount)
	}
	return nil, false, nil
}

// WasAlreadySentToDestinationShardAndUpdateState -
func (stub *DCDTNFTStorageHandlerStub) WasAlreadySentToDestinationShardAndUpdateState(tickerID []byte, nonce uint64, dstAddress []byte) (bool, error) {
	if stub.WasAlreadySentToDestinationShardAndUpdateStateCalled != nil {
		return stub.WasAlreadySentToDestinationShardAndUpdateStateCalled(tickerID, nonce, dstAddress)
	}
	return false, nil
}

// SaveNFTMetaData -
func (stub *DCDTNFTStorageHandlerStub) SaveNFTMetaData(tx data.TransactionHandler) error {
	if stub.SaveNFTMetaDataCalled != nil {
		return stub.SaveNFTMetaDataCalled(tx)
	}
	return nil
}

// AddToLiquiditySystemAcc -
func (stub *DCDTNFTStorageHandlerStub) AddToLiquiditySystemAcc(dcdtTokenKey []byte, tokenType uint32, nonce uint64, transferValue *big.Int, keepMetadataOnZeroLiquidity bool) error {
	if stub.AddToLiquiditySystemAccCalled != nil {
		return stub.AddToLiquiditySystemAccCalled(dcdtTokenKey, tokenType, nonce, transferValue, keepMetadataOnZeroLiquidity)
	}
	return nil
}

// IsInterfaceNil -
func (stub *DCDTNFTStorageHandlerStub) IsInterfaceNil() bool {
	return stub == nil
}
