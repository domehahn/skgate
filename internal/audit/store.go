package audit

import (
	"github.com/domehahn/skgate/internal/store"
)

type Store = store.FileStore

func New(dataDir string) (*Store, error) {
	return store.NewFileStore(dataDir)
}
