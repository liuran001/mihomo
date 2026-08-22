package adapter

import (
	"context"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

// stubProxy 是仅提供名字的最小 C.Proxy 实现，供分层逻辑测试使用
type stubProxy struct {
	C.Proxy
	name     string
	addr     string
	type_    C.AdapterType
	provider string
}

func (s stubProxy) Name() string           { return s.name }
func (s stubProxy) Addr() string           { return s.addr }
func (s stubProxy) Type() C.AdapterType    { return s.type_ }
func (s stubProxy) ProxyInfo() C.ProxyInfo { return C.ProxyInfo{ProviderName: s.provider} }
func (s stubProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	return 0, nil
}

func stub(name string) C.Proxy { return stubProxy{name: name, type_: C.Http} }
