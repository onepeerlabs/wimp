package manager

import (
	"bytes"
	"context"
	ipfslite "github.com/datahop/ipfs-lite/pkg"
	"github.com/onepeerlabs/wimp/pkg/encrypt"
	"io"
)

const (
	mnemonicTag        = "/mnemonic"
)

type Manager struct {
	node *ipfslite.Common
	account *encrypt.Account
}

func New(ctx context.Context, root, port, secret string) (*Manager, error) {
	err := ipfslite.Init(root, port)
	if err != nil {
		return nil, err
	}

	comm, err := ipfslite.New(ctx, root, port)
	if err != nil {
		return nil, err
	}

	// Start
	_, err = comm.Start(secret)
	if err != nil {
		return nil, err
	}

	acc := encrypt.New()
	mnemonic := bytes.NewBuffer(nil)
	mnemonicReader, _, err := comm.Node.Get(comm.Context, mnemonicTag)
	if err != nil {
		goto r
	}
	_, err = io.Copy(mnemonic, mnemonicReader)
	if err != nil {
		goto r
	}
	acc.LoadMnemonic(mnemonic.String())
r:
	return &Manager{
		node:    comm,
		account: acc,
	}, nil
}

func (m *Manager) GetNode() *ipfslite.Common {
	return m.node
}

func (m *Manager) GetAccount() *encrypt.Account {
	return m.account
}

func (m *Manager) IsInitialised() bool {
	return m.account.GetMnemonic() != ""
}
