package signing

type SigningKeyInfo interface {
	UnmarshalJSON([]byte) error
	MarshalJSON() ([]byte, error)
}

type SigningProvider interface {
	New(SigningKeyInfo) error
	Initialized() bool
	Name() string
	PublicKey() (string, error)
	SignPackage([]byte, []byte) ([]byte, error)
	SignIndex([]byte) ([]byte, error)
}
