package backends

import (
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
)

type DB struct {
	client.KeysAPI
}

func NewDB() (*DB, error) {
	db := DB{}

	cfg := client.Config{Endpoints: []string{"http://etcd1:2379,http://etcd2:2379,http://etcd3:2379"}}
	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	db.KeysAPI = client.NewKeysAPI(c)
	return &db, nil
}

func (db *DB) Get(key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := db.KeysAPI.Get(ctx, key, &client.GetOptions{
		Recursive: false,
		Sort:      false,
		Quorum:    false,
	})

	if err != nil {
		return "", err
	}

	return resp.Node.Value, nil
}

func (db *DB) Set(key, val string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.KeysAPI.Set(ctx, key, val, nil)
	return err
	/*
		if err != nil {
			if err == context.Canceled {
				// ctx is canceled by another routine
			} else if err == context.DeadlineExceeded {
				// ctx is attached with a deadline and it exceeded
			} else if cerr, ok := err.(*client.ClusterError); ok {
				// process (cerr.Errors)
			} else {
				// bad cluster endpoints, which are not etcd servers
			}
		}
	*/
}
