package alidns

import (
	"errors"
	"fmt"
	"testing"

	alidns "github.com/alibabacloud-go/alidns-20150109/v5/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockAliDNSClient struct {
	AddDomainRecordFunc       func(*alidns.AddDomainRecordRequest, *util.RuntimeOptions) (*alidns.AddDomainRecordResponse, error)
	DeleteDomainRecordFunc    func(*alidns.DeleteDomainRecordRequest, *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error)
	DescribeDomainRecordsFunc func(*alidns.DescribeDomainRecordsRequest, *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error)
}

func (m *MockAliDNSClient) AddDomainRecordWithOptions(request *alidns.AddDomainRecordRequest, runtime *util.RuntimeOptions) (*alidns.AddDomainRecordResponse, error) {
	if m.AddDomainRecordFunc != nil {
		return m.AddDomainRecordFunc(request, runtime)
	}
	return addResponse("mock-record-id"), nil
}

func (m *MockAliDNSClient) DeleteDomainRecordWithOptions(request *alidns.DeleteDomainRecordRequest, runtime *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error) {
	if m.DeleteDomainRecordFunc != nil {
		return m.DeleteDomainRecordFunc(request, runtime)
	}
	return &alidns.DeleteDomainRecordResponse{}, nil
}

func (m *MockAliDNSClient) DescribeDomainRecordsWithOptions(request *alidns.DescribeDomainRecordsRequest, runtime *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
	if m.DescribeDomainRecordsFunc != nil {
		return m.DescribeDomainRecordsFunc(request, runtime)
	}
	return describeResponse(), nil
}

func TestDescribeRecordsUsesExactSearchAndFiltersResponse(t *testing.T) {
	mockClient := &MockAliDNSClient{
		DescribeDomainRecordsFunc: func(request *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
			require.Equal(t, "example.com", tea.StringValue(request.DomainName))
			require.Equal(t, "_acme-challenge", tea.StringValue(request.KeyWord))
			require.Equal(t, "EXACT", tea.StringValue(request.SearchMode))
			require.Nil(t, request.RRKeyWord)
			require.Nil(t, request.Type)
			require.Equal(t, int64(1), tea.Int64Value(request.PageNumber))
			require.Equal(t, int64(pageSizeRequest), tea.Int64Value(request.PageSize))
			return describeResponse(
				record("exact", "_acme-challenge", "TXT", "target"),
				record("similar", "_acme-challenge-api", "TXT", "target"),
				record("wrong-type", "_acme-challenge", "A", "target"),
			), nil
		},
	}

	records, err := (&dnsProvider{client: mockClient}).DescribeRecords("example.com", "_acme-challenge")
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "exact", tea.StringValue(records[0].RecordId))
}

func TestDescribeRecordsPaginatesUsingUnfilteredCount(t *testing.T) {
	callCount := 0
	mockClient := &MockAliDNSClient{
		DescribeDomainRecordsFunc: func(request *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
			callCount++
			require.Equal(t, int64(callCount), tea.Int64Value(request.PageNumber))
			if callCount == 1 {
				return describeResponseWithTotal(3,
					record("similar", "_acme-challenge-other", "TXT", "target"),
					record("first", "_acme-challenge", "TXT", "target"),
				), nil
			}
			if callCount == 2 {
				return describeResponseWithTotal(3, record("second", "_acme-challenge", "TXT", "target")), nil
			}
			t.Fatalf("unexpected page %d", callCount)
			return nil, nil
		},
	}

	records, err := (&dnsProvider{client: mockClient}).DescribeRecords("example.com", "_acme-challenge")
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
	require.Len(t, records, 2)
	assert.Equal(t, "first", tea.StringValue(records[0].RecordId))
	assert.Equal(t, "second", tea.StringValue(records[1].RecordId))
}

func TestDescribeRecordsPropagatesPaginationError(t *testing.T) {
	wantErr := errors.New("page two failed")
	callCount := 0
	mockClient := &MockAliDNSClient{
		DescribeDomainRecordsFunc: func(_ *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
			callCount++
			if callCount == 2 {
				return nil, wantErr
			}
			return describeResponseWithTotal(2, record("first", "_acme-challenge", "TXT", "target")), nil
		},
	}

	_, err := (&dnsProvider{client: mockClient}).DescribeRecords("example.com", "_acme-challenge")
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, 2, callCount)
}

func TestAddTXTRecordConvergesDuplicatesAfterAdd(t *testing.T) {
	describeCalls := 0
	addCalls := 0
	var deleted []string
	mockClient := &MockAliDNSClient{
		DescribeDomainRecordsFunc: func(_ *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
			describeCalls++
			if describeCalls == 1 {
				return describeResponse(), nil
			}
			return describeResponse(
				record("record-20", "_acme-challenge", "TXT", "target"),
				record("record-03", "_acme-challenge", "TXT", "target"),
				record("record-11", "_acme-challenge", "TXT", "target"),
				record("other-value", "_acme-challenge", "TXT", "other"),
			), nil
		},
		AddDomainRecordFunc: func(request *alidns.AddDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.AddDomainRecordResponse, error) {
			addCalls++
			assert.Equal(t, "example.com", tea.StringValue(request.DomainName))
			assert.Equal(t, "_acme-challenge", tea.StringValue(request.RR))
			assert.Equal(t, recordType, tea.StringValue(request.Type))
			assert.Equal(t, "target", tea.StringValue(request.Value))
			return addResponse("record-20"), nil
		},
		DeleteDomainRecordFunc: func(request *alidns.DeleteDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error) {
			deleted = append(deleted, tea.StringValue(request.RecordId))
			return &alidns.DeleteDomainRecordResponse{}, nil
		},
	}

	recordID, err := (&dnsProvider{client: mockClient}).AddTXTRecord("example.com", "_acme-challenge", "target")
	require.NoError(t, err)
	assert.Equal(t, "record-03", recordID)
	assert.Equal(t, 1, addCalls)
	assert.Equal(t, 2, describeCalls)
	assert.Equal(t, []string{"record-11", "record-20"}, deleted)
}

func TestAddTXTRecordConvergesExistingDuplicatesWithoutAdd(t *testing.T) {
	addCalled := false
	var deleted []string
	mockClient := &MockAliDNSClient{
		DescribeDomainRecordsFunc: func(_ *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
			return describeResponse(
				record("z-id", "_acme-challenge", "TXT", "target"),
				record("a-id", "_acme-challenge", "TXT", "target"),
			), nil
		},
		AddDomainRecordFunc: func(_ *alidns.AddDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.AddDomainRecordResponse, error) {
			addCalled = true
			return nil, nil
		},
		DeleteDomainRecordFunc: func(request *alidns.DeleteDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error) {
			deleted = append(deleted, tea.StringValue(request.RecordId))
			return &alidns.DeleteDomainRecordResponse{}, nil
		},
	}

	recordID, err := (&dnsProvider{client: mockClient}).AddTXTRecord("example.com", "_acme-challenge", "target")
	require.NoError(t, err)
	assert.Equal(t, "a-id", recordID)
	assert.False(t, addCalled)
	assert.Equal(t, []string{"z-id"}, deleted)
}

func TestAddTXTRecordPropagatesErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "initial describe", err: errors.New("initial describe failed")},
		{name: "add", err: errors.New("add failed")},
		{name: "post-add describe", err: errors.New("post-add describe failed")},
		{name: "dedup delete", err: errors.New("delete failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			describeCalls := 0
			mockClient := &MockAliDNSClient{}
			mockClient.DescribeDomainRecordsFunc = func(_ *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
				describeCalls++
				switch tt.name {
				case "initial describe":
					return nil, tt.err
				case "post-add describe":
					if describeCalls == 2 {
						return nil, tt.err
					}
				case "dedup delete":
					return describeResponse(
						record("a-id", "_acme-challenge", "TXT", "target"),
						record("b-id", "_acme-challenge", "TXT", "target"),
					), nil
				}
				return describeResponse(), nil
			}
			mockClient.AddDomainRecordFunc = func(_ *alidns.AddDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.AddDomainRecordResponse, error) {
				if tt.name == "add" {
					return nil, tt.err
				}
				return addResponse("new-id"), nil
			}
			mockClient.DeleteDomainRecordFunc = func(_ *alidns.DeleteDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error) {
				return nil, tt.err
			}

			_, err := (&dnsProvider{client: mockClient}).AddTXTRecord("example.com", "_acme-challenge", "target")
			require.ErrorIs(t, err, tt.err)
		})
	}
}

func TestDeleteRecordsByKeyDeletesOnlyExactRRAndValue(t *testing.T) {
	var deleted []string
	mockClient := &MockAliDNSClient{
		DescribeDomainRecordsFunc: func(_ *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
			return describeResponse(
				record("target", "_acme-challenge", "TXT", "challenge-key"),
				record("other-value", "_acme-challenge", "TXT", "other-key"),
				record("similar-rr", "_acme-challenge-api", "TXT", "challenge-key"),
				record("wrong-type", "_acme-challenge", "A", "challenge-key"),
			), nil
		},
		DeleteDomainRecordFunc: func(request *alidns.DeleteDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error) {
			deleted = append(deleted, tea.StringValue(request.RecordId))
			return &alidns.DeleteDomainRecordResponse{}, nil
		},
	}

	err := (&dnsProvider{client: mockClient}).DeleteRecordsByKey("example.com", "_acme-challenge", "challenge-key")
	require.NoError(t, err)
	assert.Equal(t, []string{"target"}, deleted)
}

func TestDeleteRecordsByKeyPropagatesErrors(t *testing.T) {
	t.Run("describe", func(t *testing.T) {
		wantErr := errors.New("describe failed")
		provider := &dnsProvider{client: &MockAliDNSClient{
			DescribeDomainRecordsFunc: func(_ *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
				return nil, wantErr
			},
		}}
		require.ErrorIs(t, provider.DeleteRecordsByKey("example.com", "rr", "value"), wantErr)
	})

	t.Run("delete", func(t *testing.T) {
		wantErr := errors.New("delete failed")
		provider := &dnsProvider{client: &MockAliDNSClient{
			DescribeDomainRecordsFunc: func(_ *alidns.DescribeDomainRecordsRequest, _ *util.RuntimeOptions) (*alidns.DescribeDomainRecordsResponse, error) {
				return describeResponse(record("id", "rr", "TXT", "value")), nil
			},
			DeleteDomainRecordFunc: func(_ *alidns.DeleteDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error) {
				return nil, wantErr
			},
		}}
		require.ErrorIs(t, provider.DeleteRecordsByKey("example.com", "rr", "value"), wantErr)
	})
}

func TestDeleteRecord(t *testing.T) {
	wantErr := errors.New("delete failed")
	mockClient := &MockAliDNSClient{
		DeleteDomainRecordFunc: func(request *alidns.DeleteDomainRecordRequest, _ *util.RuntimeOptions) (*alidns.DeleteDomainRecordResponse, error) {
			assert.Equal(t, "record-id", tea.StringValue(request.RecordId))
			return nil, wantErr
		},
	}
	require.ErrorIs(t, (&dnsProvider{client: mockClient}).DeleteRecord("record-id"), wantErr)
}

func TestGetEndpoint(t *testing.T) {
	for _, tt := range []struct {
		region string
		want   string
	}{
		{region: "", want: defaultEndpoint},
		{region: "cn-hangzhou", want: "alidns.cn-hangzhou.aliyuncs.com"},
		{region: "cn-beijing", want: "alidns.cn-beijing.aliyuncs.com"},
	} {
		t.Run(fmt.Sprintf("region=%s", tt.region), func(t *testing.T) {
			t.Setenv("ALIBABA_CLOUD_REGION_ID", tt.region)
			assert.Equal(t, tt.want, getEndpoint())
		})
	}
}

func record(id, rr, recordType, value string) *alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord {
	return &alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord{
		RecordId: tea.String(id),
		RR:       tea.String(rr),
		Type:     tea.String(recordType),
		Value:    tea.String(value),
	}
}

func describeResponse(records ...*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord) *alidns.DescribeDomainRecordsResponse {
	return describeResponseWithTotal(int64(len(records)), records...)
}

func describeResponseWithTotal(total int64, records ...*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord) *alidns.DescribeDomainRecordsResponse {
	return &alidns.DescribeDomainRecordsResponse{
		Body: &alidns.DescribeDomainRecordsResponseBody{
			TotalCount: tea.Int64(total),
			DomainRecords: &alidns.DescribeDomainRecordsResponseBodyDomainRecords{
				Record: records,
			},
		},
	}
}

func addResponse(recordID string) *alidns.AddDomainRecordResponse {
	return &alidns.AddDomainRecordResponse{
		Body: &alidns.AddDomainRecordResponseBody{RecordId: tea.String(recordID)},
	}
}
