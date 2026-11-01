package standard

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"google.golang.org/protobuf/proto"
)

func ReadFile(path string) ([]byte, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(reader *os.File) {
		_ = reader.Close()
	}(reader)

	return io.ReadAll(reader)
}

func ReadAsset(file string) ([]byte, error) {
	return ReadFile(C.Path.GetAssetLocation(file))
}

func loadIP(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	var geoipList router.GeoIPList
	if err := proto.Unmarshal(geoipBytes, &geoipList); err != nil {
		return nil, err
	}

	for _, geoip := range geoipList.Entry {
		if strings.EqualFold(geoip.CountryCode, country) {
			return geoip.Cidr, nil
		}
	}

	return nil, fmt.Errorf("country %s not found", country)
}

func loadSite(geositeBytes []byte, list string) ([]*router.Domain, error) {
	var geositeList router.GeoSiteList
	if err := proto.Unmarshal(geositeBytes, &geositeList); err != nil {
		return nil, err
	}

	for _, site := range geositeList.Entry {
		if strings.EqualFold(site.CountryCode, list) {
			return site.Domain, nil
		}
	}

	return nil, fmt.Errorf("list %s not found", list)
}

func loadIPEntry(entryBytes []byte) ([]*router.CIDR, error) {
	var geoip router.GeoIP
	if err := proto.Unmarshal(entryBytes, &geoip); err != nil {
		return nil, err
	}
	return geoip.Cidr, nil
}

func loadSiteEntry(entryBytes []byte) ([]*router.Domain, error) {
	var geosite router.GeoSite
	if err := proto.Unmarshal(entryBytes, &geosite); err != nil {
		return nil, err
	}
	return geosite.Domain, nil
}

type standardLoader struct{}

func (d standardLoader) LoadSiteByPath(filename, list string) ([]*router.Domain, error) {
	path := C.Path.GetAssetLocation(filename)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	entryBytes, decodeErr := geodata.DecodeReader(f, list)
	_ = f.Close()
	if decodeErr == nil {
		return loadSiteEntry(entryBytes)
	}
	if errors.Is(decodeErr, geodata.ErrCodeNotFound) {
		return nil, fmt.Errorf("list %s not found", list)
	}
	log.Warnln("failed to decode geosite file: %s%s", filename, ", fallback to the original ReadFile method")
	geositeBytes, err := ReadAsset(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	return loadSite(geositeBytes, list)
}

func (d standardLoader) LoadSiteByBytes(geositeBytes []byte, list string) ([]*router.Domain, error) {
	entryBytes, err := geodata.DecodeBytes(geositeBytes, list)
	if err == nil {
		return loadSiteEntry(entryBytes)
	}
	if errors.Is(err, geodata.ErrCodeNotFound) {
		return nil, fmt.Errorf("list %s not found", list)
	}
	log.Warnln("failed to decode geosite data, fallback to the original method")
	return loadSite(geositeBytes, list)
}

func (d standardLoader) LoadIPByPath(filename, country string) ([]*router.CIDR, error) {
	path := C.Path.GetAssetLocation(filename)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	entryBytes, decodeErr := geodata.DecodeReader(f, country)
	_ = f.Close()
	if decodeErr == nil {
		return loadIPEntry(entryBytes)
	}
	if errors.Is(decodeErr, geodata.ErrCodeNotFound) {
		return nil, fmt.Errorf("country %s not found", country)
	}
	log.Warnln("failed to decode geoip file: %s%s", filename, ", fallback to the original ReadFile method")
	geoipBytes, err := ReadAsset(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	return loadIP(geoipBytes, country)
}

func (d standardLoader) LoadIPByBytes(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	entryBytes, err := geodata.DecodeBytes(geoipBytes, country)
	if err == nil {
		return loadIPEntry(entryBytes)
	}
	if errors.Is(err, geodata.ErrCodeNotFound) {
		return nil, fmt.Errorf("country %s not found", country)
	}
	log.Warnln("failed to decode geoip data, fallback to the original method")
	return loadIP(geoipBytes, country)
}

func init() {
	geodata.RegisterGeoDataLoaderImplementationCreator("standard", func() geodata.LoaderImplementation {
		return standardLoader{}
	})
}
