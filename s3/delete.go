package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
)

type multiDelete struct {
	XMLName xml.Name `xml:"Delete"`
	Quiet   bool
	Keys    []mdObject `xml:"Object"`
}

type mdResult struct {
	Errors []mdObject `xml:"Error"`
}

type mdObject struct {
	Key     string
	Code    string `xml:",omitempty"`
	Message string `xml:",omitempty"`
}

func (b *Bucket) DeleteMulti(keys []string) map[string]error {
	objs := make([]mdObject, len(keys))
	for i, k := range keys {
		objs[i] = mdObject{Key: k}
	}
	data, _ := xml.Marshal(&multiDelete{Quiet: true, Keys: objs})
	h := md5.New()
	h.Write(data)
	cmd5 := base64.StdEncoding.EncodeToString(h.Sum(nil))
	header := make(http.Header)
	header.Set("Content-MD5", cmd5)
	req := &request{
		bucket:  b.Name,
		method:  "POST",
		params:  url.Values{"delete": []string{""}},
		payload: bytes.NewBuffer(data),
		headers: header,
	}

	var res mdResult
	if err := b.S3.query(req, &res); err != nil {
		return map[string]error{"all": err}
	}

	var errs map[string]error
	if len(res.Errors) > 0 {
		errs = make(map[string]error, len(res.Errors))
		for _, err := range res.Errors {
			errs[err.Key] = &Error{Message: err.Message, Code: err.Code}
		}
	}
	return errs
}
