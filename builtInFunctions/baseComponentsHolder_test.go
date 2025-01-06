package builtInFunctions

import (
	"math/big"
	"testing"

	"github.com/TerraDharitri/drt-go-core/core"
	"github.com/TerraDharitri/drt-go-core/data/dcdt"
	vmcommon "github.com/TerraDharitri/drt-go-vm-common"
	"github.com/TerraDharitri/drt-go-vm-common/mock"
	"github.com/stretchr/testify/assert"
)

func TestBaseComponentsHolder_addNFTToDestination(t *testing.T) {
	t.Parallel()

	t.Run("different shards should save liquidity to system account", func(t *testing.T) {
		t.Parallel()

		saveCalled := false
		addToLiquiditySystemAccCalled := false
		b := &baseComponentsHolder{
			dcdtStorageHandler: &mock.DCDTNFTStorageHandlerStub{
				GetDCDTNFTTokenOnDestinationCalled: func(_ vmcommon.UserAccountHandler, _ []byte, _ uint64) (*dcdt.DCDigitalToken, bool, error) {
					return &dcdt.DCDigitalToken{
						Value: big.NewInt(100),
					}, false, nil
				},
				SaveDCDTNFTTokenCalled: func(_ []byte, _ vmcommon.UserAccountHandler, _ []byte, _ uint64, dcdtData *dcdt.DCDigitalToken, properties vmcommon.NftSaveArgs) ([]byte, error) {
					assert.Equal(t, big.NewInt(200), dcdtData.Value)
					saveCalled = true
					return nil, nil
				},
				AddToLiquiditySystemAccCalled: func(dcdtTokenKey []byte, _ uint32, nonce uint64, transferValue *big.Int, _ bool) error {
					assert.Equal(t, big.NewInt(100), transferValue)
					addToLiquiditySystemAccCalled = true
					return nil
				},
			},
			globalSettingsHandler: &mock.GlobalSettingsHandlerStub{
				IsPausedCalled: func(_ []byte) bool {
					return false
				},
			},
			shardCoordinator: &mock.ShardCoordinatorStub{
				SameShardCalled: func(_, _ []byte) bool {
					return false
				},
			},
			enableEpochsHandler: &mock.EnableEpochsHandlerStub{},
		}

		acc := &mock.UserAccountStub{}
		dcdtDataToTransfer := &dcdt.DCDigitalToken{
			Type:       0,
			Value:      big.NewInt(100),
			Properties: make([]byte, 0),
		}
		err := b.addNFTToDestination([]byte("sndAddr"), []byte("dstAddr"), acc, dcdtDataToTransfer, []byte("dcdtTokenKey"), 0, false)
		assert.Nil(t, err)
		assert.True(t, addToLiquiditySystemAccCalled)
		assert.True(t, saveCalled)
	})
}

func TestBaseComponentsHolder_getLatestDcdtData(t *testing.T) {
	t.Parallel()

	t.Run("flag disabled should return transfer dcdt data", func(t *testing.T) {
		t.Parallel()

		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(_ core.EnableEpochFlag) bool {
				return false
			},
		}
		currentDcdtData := &dcdt.DCDigitalToken{
			Reserved: []byte{1},
			Value:    big.NewInt(100),
		}
		transferDcdtData := &dcdt.DCDigitalToken{
			Reserved: []byte{2},
			Value:    big.NewInt(200),
		}

		latestDcdtData, err := getLatestMetaData(currentDcdtData, transferDcdtData, enableEpochsHandler, &mock.MarshalizerMock{})
		assert.Nil(t, err)
		assert.Equal(t, transferDcdtData, latestDcdtData)
	})
	t.Run("flag enabled and transfer dcdt data version is not set should merge", func(t *testing.T) {
		t.Parallel()
		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(_ core.EnableEpochFlag) bool {
				return true
			},
		}
		name := []byte("name")
		creator := []byte("creator")
		newCreator := []byte("newCreator")
		royalties := uint32(25)
		newRoyalties := uint32(11)
		hash := []byte("hash")
		uris := [][]byte{[]byte("uri1"), []byte("uri2")}
		attributes := []byte("attributes")
		newAttributes := []byte("newAttributes")
		transferDcdtData := &dcdt.DCDigitalToken{
			Reserved: []byte{1},
			TokenMetaData: &dcdt.MetaData{
				Nonce:      0,
				Name:       name,
				Creator:    creator,
				Royalties:  royalties,
				Hash:       hash,
				URIs:       uris,
				Attributes: attributes,
			},
		}
		currentDcdtVersion := &dcdt.MetaDataVersion{
			Creator:    2,
			Royalties:  2,
			Attributes: 2,
		}
		versionBytes, _ := (&mock.MarshalizerMock{}).Marshal(currentDcdtVersion)
		currentDcdtData := &dcdt.DCDigitalToken{
			Reserved: versionBytes,
			TokenMetaData: &dcdt.MetaData{
				Creator:    newCreator,
				Royalties:  newRoyalties,
				Attributes: newAttributes,
			},
		}

		latestDcdtData, err := getLatestMetaData(currentDcdtData, transferDcdtData, enableEpochsHandler, &mock.MarshalizerMock{})
		assert.Nil(t, err)
		assert.Equal(t, versionBytes, latestDcdtData.Reserved)
		assert.Equal(t, newCreator, latestDcdtData.TokenMetaData.Creator)
		assert.Equal(t, newRoyalties, latestDcdtData.TokenMetaData.Royalties)
		assert.Equal(t, newAttributes, latestDcdtData.TokenMetaData.Attributes)

		assert.Equal(t, name, latestDcdtData.TokenMetaData.Name)
		assert.Equal(t, hash, latestDcdtData.TokenMetaData.Hash)
		assert.Equal(t, uris, latestDcdtData.TokenMetaData.URIs)
	})
	t.Run("different versions for different fields should merge", func(t *testing.T) {
		t.Parallel()
		enableEpochsHandler := &mock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(_ core.EnableEpochFlag) bool {
				return true
			},
		}
		name := []byte("name")
		creator := []byte("creator")
		newCreator := []byte("newCreator")
		royalties := uint32(25)
		newRoyalties := uint32(11)
		hash := []byte("hash")
		uris := [][]byte{[]byte("uri1"), []byte("uri2")}
		attributes := []byte("attributes")
		newAttributes := []byte("newAttributes")
		transferDcdtVersion := &dcdt.MetaDataVersion{
			Name:       3,
			Creator:    0,
			Royalties:  0,
			Hash:       3,
			URIs:       3,
			Attributes: 3,
		}
		versionBytes, _ := (&mock.MarshalizerMock{}).Marshal(transferDcdtVersion)
		transferDcdtData := &dcdt.DCDigitalToken{
			Reserved: versionBytes,
			TokenMetaData: &dcdt.MetaData{
				Nonce:      0,
				Name:       name,
				Creator:    creator,
				Royalties:  royalties,
				Hash:       hash,
				URIs:       uris,
				Attributes: attributes,
			},
		}
		currentDcdtVersion := &dcdt.MetaDataVersion{
			Name:       0,
			Creator:    2,
			Royalties:  2,
			Hash:       0,
			URIs:       0,
			Attributes: 2,
		}
		versionBytes, _ = (&mock.MarshalizerMock{}).Marshal(currentDcdtVersion)
		currentDcdtData := &dcdt.DCDigitalToken{
			Reserved: versionBytes,
			TokenMetaData: &dcdt.MetaData{
				Creator:    newCreator,
				Royalties:  newRoyalties,
				Attributes: newAttributes,
			},
		}

		latestDcdtData, err := getLatestMetaData(currentDcdtData, transferDcdtData, enableEpochsHandler, &mock.MarshalizerMock{})
		assert.Nil(t, err)
		expectedVersion := &dcdt.MetaDataVersion{
			Name:       3,
			Creator:    2,
			Royalties:  2,
			Hash:       3,
			URIs:       3,
			Attributes: 3,
		}
		expectedVersionBytes, _ := (&mock.MarshalizerMock{}).Marshal(expectedVersion)
		assert.Equal(t, expectedVersionBytes, latestDcdtData.Reserved)
		assert.Equal(t, newCreator, latestDcdtData.TokenMetaData.Creator)
		assert.Equal(t, newRoyalties, latestDcdtData.TokenMetaData.Royalties)
		assert.Equal(t, name, latestDcdtData.TokenMetaData.Name)
		assert.Equal(t, hash, latestDcdtData.TokenMetaData.Hash)
		assert.Equal(t, uris, latestDcdtData.TokenMetaData.URIs)
		assert.Equal(t, attributes, latestDcdtData.TokenMetaData.Attributes)
	})
}
