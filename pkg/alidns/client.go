package alidns

import (
	"fmt"
	"os"
	"sort"

	alidns "github.com/alibabacloud-go/alidns-20150109/v5/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	credential "github.com/aliyun/credentials-go/credentials"
)

// Reference:
// https://api.aliyun.com/product/Alidns
const (
	defaultEndpoint = "alidns.aliyuncs.com"
	pageSizeRequest = 100
	recordType      = "TXT"
)

// AliDNSClient 定义阿里云 DNS 客户端接口
type AliDNSClient interface {
	AddDomainRecordWithOptions(request *alidns.AddDomainRecordRequest, runtime *util.RuntimeOptions) (*alidns.AddDomainRecordResponse, error)
	DeleteDomainRecordWithOptions(request *alidns.DeleteDomainRecordRequest, runtime *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error)
	DescribeDomainRecordsWithOptions(request *alidns.DescribeDomainRecordsRequest, runtime *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error)
}

type DNSProvider interface {
	AddTXTRecord(domain, rr, value string) (string, error)
	DeleteRecordsByKey(domain, rr, value string) error
}

// dnsProvider 是 AliDNS 的客户端封装
type dnsProvider struct {
	client AliDNSClient
}

// DNSProvider defines the interface for DNS operations

// NewDNSProvider 创建一个新的 AliDNS 客户端
func NewDNSProvider() (DNSProvider, error) {
	credential, err := credential.NewCredential(nil)
	if err != nil {
		return nil, err
	}
	endpoint := getEndpoint()

	config := &openapi.Config{
		Credential: credential,
		Endpoint:   tea.String(endpoint),
	}
	alidnsClient, err := alidns.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &dnsProvider{
		client: alidnsClient,
	}, nil
}

// AddTXTRecord 添加 TXT 记录
func (p *dnsProvider) AddTXTRecord(domain, rr, value string) (string, error) {
	records, err := p.DescribeRecords(domain, rr)
	if err != nil {
		return "", fmt.Errorf("failed to describe records: %w", err)
	}

	if recordID, found, err := p.convergeRecords(records, value); found || err != nil {
		return recordID, err
	}

	request := &alidns.AddDomainRecordRequest{
		DomainName: tea.String(domain),
		RR:         tea.String(rr),
		Type:       tea.String(recordType),
		Value:      tea.String(value),
	}

	response, err := p.client.AddDomainRecordWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to add domain record: %w", err)
	}

	createdRecordID := ""
	if response != nil && response.Body != nil && response.Body.RecordId != nil {
		createdRecordID = *response.Body.RecordId
	}

	// Re-read after creation so concurrent Present calls converge on one record.
	records, err = p.DescribeRecords(domain, rr)
	if err != nil {
		return "", fmt.Errorf("failed to describe records after add: %w", err)
	}
	if recordID, found, err := p.convergeRecords(records, value); found || err != nil {
		return recordID, err
	}
	if createdRecordID == "" {
		return "", fmt.Errorf("add domain record response did not contain a RecordId")
	}

	// AliDNS can be eventually consistent. The add response is authoritative if
	// the newly-created record is not visible in the immediate re-read.
	return createdRecordID, nil
}

// DeleteRecord 删除 TXT 记录
func (p *dnsProvider) DeleteRecord(recordId string) error {
	request := &alidns.DeleteDomainRecordRequest{
		RecordId: tea.String(recordId),
	}

	runtime := &util.RuntimeOptions{}
	_, err := p.client.DeleteDomainRecordWithOptions(request, runtime)
	if err != nil {
		return fmt.Errorf("failed to delete domain record: %w", err)
	}

	return nil
}

// DeleteRecordsByKey 根据 domain、rr、value 删除记录
func (p *dnsProvider) DeleteRecordsByKey(domain, rr, value string) error {
	records, err := p.DescribeRecords(domain, rr)
	if err != nil {
		return fmt.Errorf("failed to describe records: %w", err)
	}

	for _, record := range records {
		if record.Value == nil || *record.Value != value {
			continue
		}
		if record.RecordId == nil || *record.RecordId == "" {
			return fmt.Errorf("matching TXT record is missing RecordId")
		}
		if err := p.DeleteRecord(*record.RecordId); err != nil {
			return err
		}
	}

	return nil
}

// DescribeRecords 查询指定 RR 的精确 TXT 记录。
func (p *dnsProvider) DescribeRecords(domain, rr string) ([]*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, error) {
	var exactRecords []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord
	var recordsSeen int64

	for pageNumber := int64(1); ; pageNumber++ {
		// AliDNS EXACT mode uses KeyWord. RRKeyWord and Type are ignored in that
		// mode, so RR and TXT are also checked locally below.
		request := &alidns.DescribeDomainRecordsRequest{
			DomainName: tea.String(domain),
			KeyWord:    tea.String(rr),
			SearchMode: tea.String("EXACT"),
			PageNumber: tea.Int64(pageNumber),
			PageSize:   tea.Int64(pageSizeRequest),
		}

		response, err := p.client.DescribeDomainRecordsWithOptions(request, &util.RuntimeOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to describe domain records: %w", err)
		}
		if response == nil || response.Body == nil {
			return nil, fmt.Errorf("failed to describe domain records: empty response")
		}

		var pageRecords []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord
		if response.Body.DomainRecords != nil {
			pageRecords = response.Body.DomainRecords.Record
		}
		recordsSeen += int64(len(pageRecords))
		for _, record := range pageRecords {
			if record != nil && record.RR != nil && *record.RR == rr &&
				record.Type != nil && *record.Type == recordType {
				exactRecords = append(exactRecords, record)
			}
		}

		if response.Body.TotalCount == nil || recordsSeen >= *response.Body.TotalCount || len(pageRecords) == 0 {
			break
		}
	}

	return exactRecords, nil
}

// convergeRecords deterministically keeps the lexicographically smallest
// RecordId for value and removes all other exact RR/TXT duplicates.
func (p *dnsProvider) convergeRecords(records []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, value string) (string, bool, error) {
	matching := make([]*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, 0)
	for _, record := range records {
		if record.Value != nil && *record.Value == value {
			if record.RecordId == nil || *record.RecordId == "" {
				return "", true, fmt.Errorf("matching TXT record is missing RecordId")
			}
			matching = append(matching, record)
		}
	}
	if len(matching) == 0 {
		return "", false, nil
	}

	sort.Slice(matching, func(i, j int) bool {
		return *matching[i].RecordId < *matching[j].RecordId
	})
	keptRecordID := *matching[0].RecordId
	for _, duplicate := range matching[1:] {
		if err := p.DeleteRecord(*duplicate.RecordId); err != nil {
			return "", true, fmt.Errorf("failed to remove duplicate TXT record %s: %w", *duplicate.RecordId, err)
		}
	}

	return keptRecordID, true, nil
}

func getEndpoint() string {
	region := os.Getenv("ALIBABA_CLOUD_REGION_ID")
	if region == "" {
		return defaultEndpoint
	}
	return fmt.Sprintf("alidns.%s.aliyuncs.com", region)
}
