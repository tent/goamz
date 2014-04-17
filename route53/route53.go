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
	Auth     aws.Auth
	Endpoint string
}

const apiEndpoint = "https://route53.amazonaws.com/2013-04-01/hostedzone"

// Factory for the route53 type
func NewRoute53(auth aws.Auth) *Route53 {
	return &Route53{
		Auth:     auth,
		Endpoint: apiEndpoint,
	}
}

// General Structs used in all types of requests
type HostedZones struct {
	XMLName    xml.Name `xml:"HostedZones"`
	HostedZone []HostedZone
}

type HostedZone struct {
	XMLName                xml.Name `xml:"HostedZone"`
	Id                     string
	Name                   string
	CallerReference        string
	Config                 Config
	ResourceRecordSetCount int
}

type Config struct {
	XMLName xml.Name `xml:"Config"`
	Comment string
}

// Structs for getting the existing Hosted Zones
type ListHostedZonesResponse struct {
	XMLName     xml.Name `xml:"ListHostedZonesResponse"`
	HostedZones []HostedZones
	Marker      string
	IsTruncated bool
	NextMarker  string
	MaxItems    int
}

// Structs for Creating a New Host
type CreateHostedZoneRequest struct {
	XMLName          xml.Name `xml:"CreateHostedZoneRequest"`
	Xmlns            string   `xml:"xmlns,attr"`
	Name             string
	CallerReference  string
	HostedZoneConfig HostedZoneConfig
}

type ChangeResourceRecordSetsRequest struct {
	XMLName xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	Xmlns   string   `xml:"xmlns,attr"`
	Action  string   `xml:"ChangeBatch>Changes>Change>Action"`
	Name    string   `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>Name"`
	Type    string   `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>Type"`
	TTL     string   `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>TTL,omitempty"`
	Value   string   `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>ResourceRecords>ResourceRecord>Value"`
}

type HostedZoneConfig struct {
	XMLName xml.Name `xml:"HostedZoneConfig"`
	Comment string
}

type CreateHostedZoneResponse struct {
	XMLName       xml.Name `xml:"CreateHostedZoneResponse"`
	HostedZone    HostedZone
	ChangeInfo    ChangeInfo
	DelegationSet DelegationSet
}

type ChangeResourceRecordSetsResponse struct {
	XMLName     xml.Name `xml:"ChangeResourceRecordSetsResponse"`
	Id          string   `xml:"ChangeInfo>Id"`
	Status      string   `xml:"ChangeInfo>Status"`
	SubmittedAt string   `xml:"ChangeInfo>SubmittedAt"`
}

type ChangeInfo struct {
	XMLName     xml.Name `xml:"ChangeInfo"`
	Id          string
	Status      string
	SubmittedAt string
}

type DelegationSet struct {
	XMLName     xml.Name `xml:"DelegationSet`
	NameServers NameServers
}

type NameServers struct {
	XMLName    xml.Name `xml:"NameServers`
	NameServer []string
}

type GetHostedZoneResponse struct {
	XMLName       xml.Name `xml:"GetHostedZoneResponse"`
	HostedZone    HostedZone
	DelegationSet DelegationSet
}

type DeleteHostedZoneResponse struct {
	XMLName    xml.Name `xml:"DeleteHostedZoneResponse"`
	Xmlns      string   `xml:"xmlns,attr"`
	ChangeInfo ChangeInfo
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

// query sends the specified HTTP request to the path and signs the request
// with the required authentication and headers based on the Auth.
//
// Automatically decodes the response into the the result interface
func (r *Route53) query(method string, path string, body io.Reader, result interface{}) error {
	req, err := http.NewRequest(method, path, body)
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

	return xml.NewDecoder(res.Body).Decode(result)
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
	RequestId  string `xml:"RequestId"`
}

func (err *Error) Error() string {
	if err.Code == "" {
		return err.Message
	}
	return fmt.Sprintf("%s (%s)", err.Message, err.Code)
}

// CreateHostedZone send a creation request to the AWS Route53 API
func (r *Route53) CreateHostedZone(hostedZoneReq *CreateHostedZoneRequest) (*CreateHostedZoneResponse, error) {
	xmlBytes, err := xml.Marshal(hostedZoneReq)
	if err != nil {
		return nil, err
	}

	result := new(CreateHostedZoneResponse)
	err = r.query("POST", r.Endpoint, bytes.NewBuffer(xmlBytes), result)

	return result, err
}

// ChangeResourceRecordSet send a change resource record request to the AWS Route53 API
func (r *Route53) ChangeResourceRecordSet(req *ChangeResourceRecordSetsRequest, zoneId string) (*ChangeResourceRecordSetsResponse, error) {
	xmlBytes, err := xml.Marshal(req)
	if err != nil {
		return nil, err
	}
	xmlBytes = []byte(xml.Header + string(xmlBytes))

	result := new(ChangeResourceRecordSetsResponse)
	path := fmt.Sprintf("%s/%s/rrset", r.Endpoint, zoneId)
	err = r.query("POST", path, bytes.NewBuffer(xmlBytes), result)

	return result, err
}

// ListedHostedZones fetches a collection of HostedZones through the AWS Route53 API
func (r *Route53) ListHostedZones(marker string, maxItems int) (result *ListHostedZonesResponse, err error) {
	path := ""

	if marker == "" {
		path = fmt.Sprintf("%s?maxitems=%d", r.Endpoint, maxItems)
	} else {
		path = fmt.Sprintf("%s?marker=%v&maxitems=%d", r.Endpoint, marker, maxItems)
	}

	result = new(ListHostedZonesResponse)
	err = r.query("GET", path, nil, result)

	return
}

// GetHostedZone fetches a particular hostedzones DelegationSet by id
func (r *Route53) GetHostedZone(id string) (result *GetHostedZoneResponse, err error) {
	result = new(GetHostedZoneResponse)
	err = r.query("GET", fmt.Sprintf("%s/%v", r.Endpoint, id), nil, result)

	return
}

// DeleteHostedZone deletes the hosted zone with the given id
func (r *Route53) DeleteHostedZone(id string) (result *DeleteHostedZoneResponse, err error) {
	path := fmt.Sprintf("%s/%s", r.Endpoint, id)

	result = new(DeleteHostedZoneResponse)
	err = r.query("DELETE", path, nil, result)

	return
}
