package route53

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cupcake/goamz/aws"
)

type Route53 struct {
	Auth    aws.Auth
	BaseURL string
}

const (
	apiBase         = "https://route53.amazonaws.com/2013-04-01"
	hostedZonePath  = "/hostedzone"
	healthCheckPath = "/healthcheck"
	changePath      = "/change"
)

func NewRoute53(auth aws.Auth) *Route53 {
	return &Route53{
		Auth:    auth,
		BaseURL: apiBase,
	}
}

type HostedZones struct {
	HostedZone []HostedZone
}

type HostedZone struct {
	Id                     string
	Name                   string
	CallerReference        string
	Config                 Config
	ResourceRecordSetCount int
}

type Config struct {
	Comment string
}

type ListHostedZonesResponse struct {
	HostedZones []HostedZones
	Marker      string
	IsTruncated bool
	NextMarker  string
	MaxItems    int
}

type CreateHostedZoneRequest struct {
	Name             string
	CallerReference  string
	HostedZoneConfig HostedZoneConfig
}

type ChangeResourceRecordSetsRequest struct {
	Changes []ResourceRecordSetChange `xml:"ChangeBatch>Changes>Change"`
}

type ResourceRecordSetChange struct {
	Action            string
	ResourceRecordSet ResourceRecordSet
}

type ResourceRecordSet struct {
	Name          string
	Type          string
	TTL           string       `xml:",omitempty"`
	Values        []string     `xml:"ResourceRecords>ResourceRecord>Value"`
	SetId         string       `xml:"SetIdentifier,omitempty"`
	Weight        int          `xml:",omitempty"`
	Region        string       `xml:",omitempty"`
	Failover      string       `xml:",omitempty"`
	HealthCheckId string       `xml:",omitempty"`
	AliasTarget   *AliasTarget `xml:",omitempty"`
}

type AliasTarget struct {
	HostedZoneId         string
	DNSName              string
	EvaluateTargetHealth bool
}

type HostedZoneConfig struct {
	Comment string
}

type CreateHostedZoneResponse struct {
	HostedZone    HostedZone
	ChangeInfo    ChangeInfo
	DelegationSet DelegationSet
}

type changeResourceRecordSetsResponse struct {
	ChangeInfo ChangeInfo
}

type ChangeInfo struct {
	Id          string
	Status      string
	SubmittedAt string
}

type DelegationSet struct {
	NameServers NameServers
}

type NameServers struct {
	NameServer []string
}

type GetHostedZoneResponse struct {
	HostedZone    HostedZone
	DelegationSet DelegationSet
}

type DeleteHostedZoneResponse struct {
	ChangeInfo ChangeInfo
}

type getChangeResponse struct {
	ChangeInfo ChangeInfo
}

type HealthCheck struct {
	XMLName          xml.Name
	Id               string `xml:",omitempty`
	CallerReference  string
	IPAddress        string `xml:"HealthCheckConfig>IPAddress"`
	Port             int    `xml:"HealthCheckConfig>Port,omitempty"`
	Type             string `xml:"HealthCheckConfig>Type"`
	ResourcePath     string `xml:"HealthCheckConfig>ResourcePath,omitempty"`
	FQDN             string `xml:"HealthCheckConfig>FullyQualifiedDomainName,omitempty"`
	SearchString     string `xml:"HealthCheckConfig>SearchString,omitempty"`
	RequestInterval  int    `xml:"HealthCheckConfig>RequestInterval,omitempty"`
	FailureThreshold int    `xml:"HealthCheckConfig>FailureThreshold,omitempty"`
}

type healthCheckWrapper struct {
	HealthCheck HealthCheck
}

func (r *Route53) sign(req *http.Request) {
	date := time.Now().Format(time.RFC1123)
	h := hmac.New(sha256.New, []byte(r.Auth.SecretKey))
	h.Write([]byte(date))
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))

	authHeader := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s,Algorithm=%s,Signature=%s", r.Auth.AccessKey, "HmacSHA256", sig)
	req.Header.Set("Date", date)
	req.Header.Set("X-Amzn-Authorization", authHeader)
}

func (r *Route53) queryZone(method, path string, in, out interface{}) error {
	return r.query(method, hostedZonePath+path, in, out)
}

func (r *Route53) queryHealthCheck(method, path string, in, out interface{}) error {
	return r.query(method, healthCheckPath+path, in, out)
}

func (r *Route53) query(method, path string, in, out interface{}) error {
	var body io.Reader
	if in != nil {
		var buf bytes.Buffer
		buf.WriteString(xml.Header)
		if err := xml.NewEncoder(&buf).Encode(in); err != nil {
			return err
		}
		body = &buf
	}

	req, err := http.NewRequest(method, r.BaseURL+path, body)
	r.sign(req)
	req.Header.Set("Content-Type", "application/xml")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	if res.StatusCode != 201 && res.StatusCode != 200 {
		return buildError(res)
	}

	return xml.NewDecoder(res.Body).Decode(out)
}

func buildError(r *http.Response) error {
	err := &Error{}
	xml.NewDecoder(r.Body).Decode(err)
	err.StatusCode = r.StatusCode
	if err.Message == "" {
		err.Message = r.Status
	}
	return err
}

type Error struct {
	StatusCode int
	Type       string `xml:"Error>Type"`
	Code       string `xml:"Error>Code"`
	Message    string `xml:"Error>Message"`
	RequestId  string
}

func (err *Error) Error() string {
	if err.Code == "" {
		return err.Message
	}
	return fmt.Sprintf("%s (%s)", err.Message, err.Code)
}

func (r *Route53) CreateHostedZone(hostedZoneReq *CreateHostedZoneRequest) (*CreateHostedZoneResponse, error) {
	res := &CreateHostedZoneResponse{}
	return res, r.queryZone("POST", "", hostedZoneReq, res)
}

func (r *Route53) ChangeResourceRecordSet(req *ChangeResourceRecordSetsRequest, zoneId string) (*ChangeInfo, error) {
	res := &changeResourceRecordSetsResponse{}
	return &res.ChangeInfo, r.queryZone("POST", fmt.Sprintf("/%s/rrset", zoneId), req, res)
}

func (r *Route53) ListHostedZones(marker string, maxItems int) (*ListHostedZonesResponse, error) {
	var path string
	if marker == "" {
		path = fmt.Sprintf("?maxitems=%d", maxItems)
	} else {
		path = fmt.Sprintf("?marker=%v&maxitems=%d", marker, maxItems)
	}
	res := &ListHostedZonesResponse{}
	return res, r.queryZone("GET", path, nil, res)
}

func (r *Route53) GetHostedZone(id string) (*GetHostedZoneResponse, error) {
	res := &GetHostedZoneResponse{}
	return res, r.queryZone("GET", "/"+id, nil, res)
}

func (r *Route53) DeleteHostedZone(id string) (*DeleteHostedZoneResponse, error) {
	res := &DeleteHostedZoneResponse{}
	return res, r.queryZone("DELETE", "/"+id, nil, res)
}

func (r *Route53) CreateHealthCheck(check *HealthCheck) (*HealthCheck, error) {
	check.XMLName.Local = "CreateHealthCheckRequest"
	res := &healthCheckWrapper{}
	err := r.queryHealthCheck("POST", "", check, res)
	return &res.HealthCheck, err
}

func (r *Route53) DeleteHealthCheck(id string) error {
	return r.queryHealthCheck("DELETE", "/"+id, nil, &struct{}{})
}

func (r *Route53) GetHealthCheck(id string) (*HealthCheck, error) {
	res := &healthCheckWrapper{}
	err := r.queryHealthCheck("GET", "/"+id, nil, res)
	return &res.HealthCheck, err
}

func (r *Route53) GetChange(id string) (*ChangeInfo, error) {
	res := &getChangeResponse{}
	err := r.query("GET", changePath+"/"+id, nil, res)
	return &res.ChangeInfo, err
}
