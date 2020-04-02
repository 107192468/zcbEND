package pkcs8

import (
	"bytes"
	"testing"

	"encoding/json"
	"fmt"
	"io/ioutil"
)

var publicKey *bytes.Buffer = bytes.NewBufferString(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1yaXfdyMW42BuLHdBRPT
Fdu5263+HgZZ3LflXinKZWw4k1ZYi7PYnVFtdqTDPT9BXuVbim6IPj02NTllw8kQ
AE7AYV6GjSbr83JvgUTIaSL1InIo5ZoqOFa8G+VMju/RLkTkyx5xGMRILEpWE7pL
w1OUgFECNZXYoEL3/MMiJwVI3T3mXTCRNIsymogoUSj3jDznc3IhMs6C7d0Vt2WV
LkXKqujD7EhzOZhXJCK48WOYonAkZQUQ3hBbenPuDquDa6sAObKu7yVpx1XxNECv
WwvR2a2qwx2eSu/5stEKAYhidnta9XoEqQqzWuSOTf9wd4ggan6FwLzxFbWe70H0
BwIDAQAB
-----END PUBLIC KEY-----`)
var privateKey *bytes.Buffer = bytes.NewBufferString(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDXJpd93IxbjYG4
sd0FE9MV27nbrf4eBlnct+VeKcplbDiTVliLs9idUW12pMM9P0Fe5VuKbog+PTY1
OWXDyRAATsBhXoaNJuvzcm+BRMhpIvUicijlmio4Vrwb5UyO79EuROTLHnEYxEgs
SlYTukvDU5SAUQI1ldigQvf8wyInBUjdPeZdMJE0izKaiChRKPeMPOdzciEyzoLt
3RW3ZZUuRcqq6MPsSHM5mFckIrjxY5iicCRlBRDeEFt6c+4Oq4NrqwA5sq7vJWnH
VfE0QK9bC9HZrarDHZ5K7/my0QoBiGJ2e1r1egSpCrNa5I5N/3B3iCBqfoXAvPEV
tZ7vQfQHAgMBAAECggEAPCfaK6LCy8ZhAtcYSRcl6fKpoLahWpvD/GaehxmAMaN0
nh2CXG1In5Po20duH23URUgztBz7kwtiYLdPsNJC2xMpzw+y5zx+tG7Gpoooztyr
VZo9vRTBwUbfCZ2vLjf3cMxqfDBixt36oAeY0aNBE7gGyWndCEaBby3KUK3umqHo
DK9gMijJqMlpaKw9Rb4ZmL1ds/Qt7IOnfgG8senUP6ZHgfgz3aimFJIh6kMugPFa
pZZ6qvUkyWuoLaZFgCxUYyGBRDYIhWZpLM0HOsTY78YdOA5aGIAikuy4jlGYh3WL
iTi/Iieptf/XVVmpregq9cL71C5suA9tbiyw12oogQKBgQDaUuLhTp6zGeY+s+bA
yaD0E83kTG920+uBDvcRpKevdOIP5dYv96hZOGxTzF/2ShaiP4b46Uej5qRdKTG6
rtwd0lwQieD4r7XIojej3RmjQyah5ZAsjBJnpRbOBVL0oNfdxJChiywtnp9NsMaV
9mNxb/NCAAaUzg29or0ZAsp99wKBgQD8R4cLEiHvvblRwVVgWUTZ9zDWF53FPZ1D
5rR3QMENb7NRmDPby4tRFpJ3vdf8NhVrpMf4xwRYQQN4Sq+hpzP6eovX205SHQbs
tbZ4mMISHrnrhcCV3psRuOoN9hw/nEmm21J+eVp4r94M59qWuHwTLSni9D6XuVis
W4a0BpP2cQKBgG5IakTnovDTx2OrGogOEdjZXCrTlYaP3CmwNovaAb52q27eaciH
MKoI/2eBGIRfvnks3/BCXqbjbemFUpJ7m8MQrOLJ0zOsBoaXssV6fWXkGNK1FJP8
GZvzX8aoF9Rsnz5t+aUwmRteQhhLkLTV5ju6EkYnnytxvq0pVJ4as9DXAoGADgj0
rFr/5FSLwM6er1OIDxA/eUmrD1QUMbjeBVxm4RZ7xWhQSkQSpho5X8wB/hgMLQbn
0SFRTo+fX8vX5YhlzeOPcBzVSKAwyG57jk4BTfzDnyS7yBqwSdYdv1UX0ToiptPA
zSR3MgumsNUdRhFRZce3ctbfvJUlJ8GXxuAuzyECgYBUFJcuJG7pvb0U/Mt9oSM2
fW6mgFAeHicZz1NCU+HSOHY+Z6NaqHOx56a9UTY9Q5Lj5+/kNt7onBcABKHkQrmZ
T4+2S1E7sMrDZKOUkhrRpcz4K4Nzt1IZ5IpZlFdrz2KCxkJpF/O/VSoy3ziH1xIr
wHig1noQRHCPtouAsJSn3g==
-----END PRIVATE KEY-----`)
var xrsa *PKCS8Rsa

func TestCreateKeys(t *testing.T) {
	err := CreateKeys(publicKey, privateKey, 2048)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(publicKey.String())
	t.Log(privateKey.String())
}

func TestNewXRsa(t *testing.T) {
	var err error
	xrsa, err = NewPKCS8Rsa(publicKey.Bytes(), privateKey.Bytes())
	if err != nil {
		t.Error(err.Error())
	}
}

func TestPublicEncryptDecrypt(t *testing.T) {
	//err := CreateKeys(publicKey, privateKey, 2048)
	xrsa, err := NewPKCS8Rsa(publicKey.Bytes(), privateKey.Bytes())
	if err != nil {
		t.Error(err.Error())
	}
	data := "这个世界很美好"
	encrypted, err := xrsa.PublicEncrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypted, err := xrsa.PrivateDecrypt(encrypted)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(decrypted) != data {
		t.Fatal(fmt.Sprintf("Faildassert\"%s\"equals\"%s\"", decrypted, data))
	}
}

func TestPrivateEncryptDecrypt(t *testing.T) {
	data := "Estimatesofthenumberoflanguages中国intheworldvarybetween5,000and7,000.However,anypreciseestimatedependsonapartlyarbitrarydistinctionbetweenlanguagesanddialects.Naturallanguagesarespokenorsigned,butanylanguagecanbeencodedintosecondarymediausingauditory,visual,ortactilestimuli–forexample,inwhistling,signed,orbraille.Thisisbecausehumanlanguageismodality-independent.Dependingonphilosophicalperspectivesregardingthedefinitionoflanguageandmeaning,whenusedasageneralconcept,languagemayrefertothecognitiveabilitytolearnandusesystemsofcomplexcommunication,ortodescribethesetofrulesthatmakesupthesesystems,orthesetofutterancesthatcanbeproducedfromthoserules.Alllanguagesrelyontheprocessofsemiosistorelatesignstoparticularmeanings.Oral,manualandtactilelanguagescontainaphonologicalsystemthatgovernshowsymbolsareusedtoformsequencesknownaswordsormorphemes,andasyntacticsystemthatgovernshowwordsandmorphemesarecombinedtoformphrasesandutterances."
	encrypted, err := xrsa.PrivateEncrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypted, err := xrsa.PublicDecrypt(encrypted)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(decrypted) != data {
		t.Fatal(fmt.Sprintf("Faildassert\"%s\"equals\"%s\"", decrypted, data))
	}
}

func TestSignVerify(t *testing.T) {
	data := "Hello,World"
	sign, err := xrsa.Sign(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = xrsa.Verify(data, sign)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestCrossLanguage(t *testing.T) {
	var data = make(map[string]string)
	pubKey, err := ioutil.ReadFile("../../test/pub.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	priKey, err := ioutil.ReadFile("../../test/pri.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	testData, err := ioutil.ReadFile("../../test/data.json")
	if err != nil {
		t.Fatal(err.Error())
	}
	err = json.Unmarshal(testData, &data)
	if err != nil {
		t.Fatal(err.Error())
	}

	rsa2, err := NewPKCS8Rsa(pubKey, priKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypted, err := rsa2.PrivateDecrypt(data["encrypted"])
	if err != nil {
		t.Fatal(err.Error())
	}
	if string(decrypted) != data["data"] {
		t.Fatal(fmt.Sprintf("Faildassert\"%s\"equals\"%s\"", decrypted, data))
	}

	decrypted, err = rsa2.PublicDecrypt(data["private_encrypted"])
	if err != nil {
		t.Fatal(err.Error())
	}
	if string(decrypted) != data["data"] {
		t.Fatal(fmt.Sprintf("Faildassert\"%s\"equals\"%s\"", decrypted, data))
	}

	err = rsa2.Verify(data["data"], data["sign"])
	if err != nil {
		t.Fatal(err.Error())
	}
}
func TestPKCS8Rsa_PrivateDecrypt(t *testing.T) {
	xrsa, err := NewPKCS8Rsa(publicKey.Bytes(), privateKey.Bytes())
	if err != nil {
		t.Error(err.Error())
	}
	encrypted := "SdqiVZBmR2bh6Q1qbT8k8bz1DVStigLEs1Ygs8JxV4hYQas0OvWRO2wrAK2noO/zKmPkXuzZRz6LCIcqUGrlDMHoDFa9XQEGUAcNiThMF2DBq5mFFZmeuVyblBCtj0ZGPMDwWiuor2qevsX5wDJAUwsMyNhBl/0h4F6djQCQgonHK7sinneU3Y3X/UO0JhL+sWcYmUhWZNX5/ojrQP+jBLd6lyaua1sdpcthr0hTUpUuQxFvY3ZPPLP5Sm7YrdKRBHzbgdktcEBF9EhbYweZnncxmlgqOkdRTBzmSv+KnLSyGonsbVIwBeXkuCWI6eAgqghtjKrtJPM8/cKtp9hQpw=="
	decrypted, err := xrsa.PrivateDecrypt(encrypted)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(decrypted)
}
