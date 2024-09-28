package cfapi

import (
	"net/http"
)

type Builder struct {
	hc         *http.Client
	serviceKey []byte
}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) WithServiceKey(key []byte) *Builder {
	b.serviceKey = key
	return b
}

func (b *Builder) WithClient(hc *http.Client) *Builder {
	b.hc = hc
	return b
}

func (b *Builder) Clone() *Builder {
	return &Builder{
		hc:         b.hc,
		serviceKey: b.serviceKey,
	}
}

func (b *Builder) Build() *Client {
	return New(WithServiceKey(b.serviceKey), WithClient(b.hc))
}
