package builtInFunctions

import (
	"errors"
	"math/big"

	"github.com/TerraDharitri/drt-go-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
)

type baseComponentsHolder struct {
	dcdtStorageHandler    vmcommon.DCDTNFTStorageHandler
	globalSettingsHandler vmcommon.GlobalMetadataHandler
	shardCoordinator      vmcommon.Coordinator
	enableEpochsHandler   vmcommon.EnableEpochsHandler
	marshaller            vmcommon.Marshalizer
}

func (b *baseComponentsHolder) addNFTToDestination(
	sndAddress []byte,
	dstAddress []byte,
	userAccount vmcommon.UserAccountHandler,
	dcdtDataToTransfer *dcdt.DCDigitalToken,
	dcdtTokenKey []byte,
	nonce uint64,
	isReturnWithError bool,
) error {
	currentDCDTData, isNew, err := b.dcdtStorageHandler.GetDCDTNFTTokenOnDestination(userAccount, dcdtTokenKey, nonce)
	if err != nil && !errors.Is(err, ErrNFTTokenDoesNotExist) {
		return err
	}
	err = checkFrozeAndPause(dstAddress, dcdtTokenKey, currentDCDTData, b.globalSettingsHandler, isReturnWithError)
	if err != nil {
		return err
	}

	transferValue := big.NewInt(0).Set(dcdtDataToTransfer.Value)
	dcdtDataToTransfer.Value.Add(dcdtDataToTransfer.Value, currentDCDTData.Value)

	if isNew && !metaDataOnUserAccount(dcdtDataToTransfer.Type) {
		dcdtDataInSystemAcc, err := b.dcdtStorageHandler.GetMetaDataFromSystemAccount(dcdtTokenKey, nonce)
		if err != nil {
			return err
		}
		if dcdtDataInSystemAcc != nil {
			currentDCDTData.TokenMetaData = dcdtDataInSystemAcc.TokenMetaData
			currentDCDTData.Reserved = dcdtDataInSystemAcc.Reserved
		}
	}

	latestDcdtData, err := getLatestMetaData(currentDCDTData, dcdtDataToTransfer, b.enableEpochsHandler, b.marshaller)
	if err != nil {
		return err
	}
	latestDcdtData.Value.Set(dcdtDataToTransfer.Value)

	properties := vmcommon.NftSaveArgs{
		MustUpdateAllFields:         false,
		IsReturnWithError:           isReturnWithError,
		KeepMetaDataOnZeroLiquidity: false,
	}

	_, err = b.dcdtStorageHandler.SaveDCDTNFTToken(sndAddress, userAccount, dcdtTokenKey, nonce, latestDcdtData, properties)
	if err != nil {
		return err
	}

	isSameShard := b.shardCoordinator.SameShard(sndAddress, dstAddress)
	if !isSameShard {
		err = b.dcdtStorageHandler.AddToLiquiditySystemAcc(dcdtTokenKey, latestDcdtData.Type, nonce, transferValue, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func getLatestMetaData(currentDcdtData, transferDcdtData *dcdt.DCDigitalToken, enableEpochsHandler vmcommon.EnableEpochsHandler, marshaller vmcommon.Marshalizer) (*dcdt.DCDigitalToken, error) {
	if !enableEpochsHandler.IsFlagEnabled(DynamicDcdtFlag) {
		return transferDcdtData, nil
	}

	return mergeDcdtData(currentDcdtData, transferDcdtData, enableEpochsHandler, marshaller)
}

func mergeDcdtData(currentDcdtData, transferDcdtData *dcdt.DCDigitalToken, enableEpochsHandler vmcommon.EnableEpochsHandler, marshaller vmcommon.Marshalizer) (*dcdt.DCDigitalToken, error) {
	if currentDcdtData.TokenMetaData == nil {
		return transferDcdtData, nil
	}

	currentMetaDataVersion, wasCurrentMetaDataUpdated, err := getMetaDataVersion(currentDcdtData, enableEpochsHandler, marshaller)
	if err != nil {
		return nil, err
	}
	transferredMetaDataVersion, wasTransferMetaDataUpdated, err := getMetaDataVersion(transferDcdtData, enableEpochsHandler, marshaller)
	if err != nil {
		return nil, err
	}

	if !wasCurrentMetaDataUpdated && !wasTransferMetaDataUpdated {
		return transferDcdtData, nil
	}

	if currentMetaDataVersion.Name > transferredMetaDataVersion.Name {
		transferDcdtData.TokenMetaData.Name = currentDcdtData.TokenMetaData.Name
		transferredMetaDataVersion.Name = currentMetaDataVersion.Name
	}
	if currentMetaDataVersion.Creator > transferredMetaDataVersion.Creator {
		transferDcdtData.TokenMetaData.Creator = currentDcdtData.TokenMetaData.Creator
		transferredMetaDataVersion.Creator = currentMetaDataVersion.Creator
	}
	if currentMetaDataVersion.Royalties > transferredMetaDataVersion.Royalties {
		transferDcdtData.TokenMetaData.Royalties = currentDcdtData.TokenMetaData.Royalties
		transferredMetaDataVersion.Royalties = currentMetaDataVersion.Royalties
	}
	if currentMetaDataVersion.Hash > transferredMetaDataVersion.Hash {
		transferDcdtData.TokenMetaData.Hash = currentDcdtData.TokenMetaData.Hash
		transferredMetaDataVersion.Hash = currentMetaDataVersion.Hash
	}
	if currentMetaDataVersion.URIs > transferredMetaDataVersion.URIs {
		transferDcdtData.TokenMetaData.URIs = currentDcdtData.TokenMetaData.URIs
		transferredMetaDataVersion.URIs = currentMetaDataVersion.URIs
	}
	if currentMetaDataVersion.Attributes > transferredMetaDataVersion.Attributes {
		transferDcdtData.TokenMetaData.Attributes = currentDcdtData.TokenMetaData.Attributes
		transferredMetaDataVersion.Attributes = currentMetaDataVersion.Attributes
	}

	err = changeDcdtVersion(transferDcdtData, transferredMetaDataVersion, enableEpochsHandler, marshaller)
	if err != nil {
		return nil, err
	}

	return transferDcdtData, nil
}
