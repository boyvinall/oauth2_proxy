package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitly/oauth2_proxy/api"
)

type GenericProvider struct {
	*ProviderData
}

func NewGenericProvider(p *ProviderData) (*GenericProvider, error) {
	p.ProviderName = "Generic"
	if p.LoginURL.String() == "" {
		return nil, fmt.Errorf("missing setting: login-url")
	}
	if p.RedeemURL.String() == "" {
		return nil, fmt.Errorf("missing setting: redeem-url")
	}
	// if p.ProfileURL.String() == "" {
	// 	p.ProfileURL = &url.URL{Scheme: "https",
	// 		Host: "www.linkedin.com",
	// 		Path: "/v1/people/~/email-address"}
	// }
	if p.ValidateURL.String() == "" {
		return nil, fmt.Errorf("missing setting: validate-url")
	}
	if p.Scope == "" {
		p.Scope = "openid offline"
	}
	return &GenericProvider{ProviderData: p}, nil
}

func getGenericHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	// header.Set("x-li-format", "json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *GenericProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.SetBasicAuth(p.ClientID, p.ClientSecret)
	fmt.Println("signing redeem with client id/secret", p.RedeemURL.String())

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	fmt.Println("got:", string(body))
	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		IdToken     string `json:"id_token,omitempty"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &SessionState{
			AccessToken: jsonResponse.AccessToken,
			Email:       p.EmailFromIdToken(jsonResponse.IdToken),
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

func (p *GenericProvider) EmailFromIdToken(idToken string) string {

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
	b, err := jwtDecodeSegment(jwt[1])
	if err != nil {
		return ""
	}
	fmt.Println("segment", string(b))

	var email struct {
		Email   string `json:"email,omitempty"`
		Subject string `json:"sub,omitempty"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return ""
	}
	if email.Email != "" {
		return email.Email
	}
	if email.Subject != "" {
		return email.Subject // ok, it's not technically an email, but ...
	}
	return ""
}

func (p *GenericProvider) GetEmailAddress(s *SessionState) (string, error) {
	if p.ProfileURL.String() == "" {
		return "", nil
	}
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String()+"?format=json", nil)
	if err != nil {
		return "", err
	}
	req.Header = getGenericHeader(s.AccessToken)

	json, err := api.Request(req)
	if err != nil {
		return "", err
	}

	email, err := json.String()
	if err != nil {
		return "", err
	}
	return email, nil
}

func (p *GenericProvider) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, getGenericHeader(s.AccessToken))
}
