package builtInFunctions

const lengthOfDCDTMetadata = 2

const (
	// MetadataPaused is the location of paused flag in the dcdt global meta data
	MetadataPaused = 1
	// MetadataLimitedTransfer is the location of limited transfer flag in the dcdt global meta data
	MetadataLimitedTransfer = 2
	// BurnRoleForAll is the location of burn role for all flag in the dcdt global meta data
	BurnRoleForAll = 4
)

const (
	// MetadataFrozen is the location of frozen flag in the dcdt user meta data
	MetadataFrozen = 1
)

const (
	flagsByte     = 0
	tokenTypeByte = 1
)

// DCDTGlobalMetadata represents dcdt global metadata saved on system account
type DCDTGlobalMetadata struct {
	Paused          bool
	LimitedTransfer bool
	BurnRoleForAll  bool
	TokenType       byte
}

// DCDTGlobalMetadataFromBytes creates a metadata object from bytes
func DCDTGlobalMetadataFromBytes(bytes []byte) DCDTGlobalMetadata {
	if len(bytes) != lengthOfDCDTMetadata {
		return DCDTGlobalMetadata{}
	}

	return DCDTGlobalMetadata{
		Paused:          (bytes[flagsByte] & MetadataPaused) != 0,
		LimitedTransfer: (bytes[flagsByte] & MetadataLimitedTransfer) != 0,
		BurnRoleForAll:  (bytes[flagsByte] & BurnRoleForAll) != 0,
		TokenType:       bytes[tokenTypeByte],
	}
}

// ToBytes converts the metadata to bytes
func (metadata *DCDTGlobalMetadata) ToBytes() []byte {
	bytes := make([]byte, lengthOfDCDTMetadata)

	if metadata.Paused {
		bytes[flagsByte] |= MetadataPaused
	}
	if metadata.LimitedTransfer {
		bytes[flagsByte] |= MetadataLimitedTransfer
	}
	if metadata.BurnRoleForAll {
		bytes[flagsByte] |= BurnRoleForAll
	}
	bytes[tokenTypeByte] = metadata.TokenType

	return bytes
}

// DCDTUserMetadata represents dcdt user metadata saved on every account
type DCDTUserMetadata struct {
	Frozen bool
}

// DCDTUserMetadataFromBytes creates a metadata object from bytes
func DCDTUserMetadataFromBytes(bytes []byte) DCDTUserMetadata {
	if len(bytes) != lengthOfDCDTMetadata {
		return DCDTUserMetadata{}
	}

	return DCDTUserMetadata{
		Frozen: (bytes[flagsByte] & MetadataFrozen) != 0,
	}
}

// ToBytes converts the metadata to bytes
func (metadata *DCDTUserMetadata) ToBytes() []byte {
	bytes := make([]byte, lengthOfDCDTMetadata)

	if metadata.Frozen {
		bytes[flagsByte] |= MetadataFrozen
	}

	return bytes
}
