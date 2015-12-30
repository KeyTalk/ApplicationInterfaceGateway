package backends

import (
	"encoding/pem"
	"time"

	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
)

type CacheManager struct {
	client.KeysAPI
}

func (cm *CacheManager) GetBytes(key string) ([]byte, error) {
	resp, err := cm.KeysAPI.Get(context.Background(), key, nil)
	if err != nil {
		return nil, err
	}

	return []byte(resp.Node.Value), nil
}

func (cm *CacheManager) Set(key string, val interface{}) error {
	var s string
	switch val.(type) {
	case *pem.Block:
		s = string(pem.EncodeToMemory(val.(*pem.Block)))
	}

	_, err := cm.KeysAPI.Set(context.Background(), key, s, &client.SetOptions{TTL: time.Hour * 12})
	return err
}

func NewCacheManager() (*CacheManager, error) {
	cfg := client.Config{
		Endpoints: []string{"http://127.0.0.1:2379"},
		Transport: client.DefaultTransport,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}

	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	kapi := client.NewKeysAPI(c)

	return &CacheManager{
		kapi,
	}, nil
}
