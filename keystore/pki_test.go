package keystore

import (
	"bytes"
	"fmt"
	"testing"
)

var keysTestCases = []struct {
	name          string
	publicKeyPem  string
	privateKeyPem string
	wantErr       bool
}{
	{
		name: "TestRSA",
		publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBuCeEl1Gu4355usZGRnbmY
j+NOhKwcam/BeCGeoOaeT5OJmZMyc4o+iocR6rxj33hN2a2A+abnRT++gIsYRni6
t/PDMRLrH+enAWi42GwizE5a6PE2aoVChxCgBhOkgxDjPDcToBFwa5wx8Q6crJ95
lijP3y3BIL3Y6m07ruQA5Yv1D/yIjuoHE8WPLmtIOmNaz4Dq9bSbYsMgjV3W8f/J
BaqMmqoMC4AS1dkv0h4n3jTcowvngn/i2bN/zea4qMNBmeG8t6gwoN9l7L3Uw9yf
/LCi5aHn59UkVQoY576D8CnX/b9sNSRlODvuSx2jojeE1lHmAd8OeuCiBhUgt+Lv
AgMBAAE=
-----END PUBLIC KEY-----`,
		privateKeyPem: `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBuCeEl1Gu4355usZGRnbmYj+NOhKwcam/BeCGeoOaeT5OJmZMy
c4o+iocR6rxj33hN2a2A+abnRT++gIsYRni6t/PDMRLrH+enAWi42GwizE5a6PE2
aoVChxCgBhOkgxDjPDcToBFwa5wx8Q6crJ95lijP3y3BIL3Y6m07ruQA5Yv1D/yI
juoHE8WPLmtIOmNaz4Dq9bSbYsMgjV3W8f/JBaqMmqoMC4AS1dkv0h4n3jTcowvn
gn/i2bN/zea4qMNBmeG8t6gwoN9l7L3Uw9yf/LCi5aHn59UkVQoY576D8CnX/b9s
NSRlODvuSx2jojeE1lHmAd8OeuCiBhUgt+LvAgMBAAECggEAGZJWLjJlLjtZWCQP
ziU3Qkr96ftO+/OIMQ+30GNX9KZNhQaZfHn5QHt01CcWzKbcEEtr1LMvpEMlgyHg
MS3/VHT3Qv8ehGGPtfHP4lT5HEUaWGoV1C2A9mro5CdFXU/QFt6hdgAWzWdUjw6T
9Ljw/pJ0vYoB2gW/2K7x35LPDZ38mCKxnw2J2ZQBx9vvAiKAdi+lV3uN2gyXrhl5
fKAIR5aVsF54i0BlEKRMH7H0uU+pA4NR5NMYJGD4CJzEjJ65C2LfSsHEXt53YPDT
/7vNbPVHeTU8lyf6rMwXFF++S2lPhNV9DGRGa9L/OpzRU14K18gUtS1gqu9Vzpon
h8G6wQKBgQCrP+vO7VjpuOReFc4ghzmaJtleHCtpzvr621E6A+at8kegZvuePSSG
e69mbLegEC1GKy+NqAiQXunXxSDQEy9daDZiNgPO5MpbbIKySgpZKLDWnho9lVIx
+UeGdwIvxAXAL9SR58ob+G+20rRhqyKGmJHJWlCJX1EjSFp8REF5sQKBgQCkfvYX
l0IWpHwQTiX76zw+9GwCFCD4X8dULSUm+5hup91Q/1PtsPdxQKmC7rRavSbbvyDF
AtjBXe4abv0ljKSRnifIC8+7kT6o1FSMJ4WN8SYxP7b0ozDJYO3qXFxz5zi6COVn
+xEgBeOH8C/3KyvpcAAlfH76Tj4iGqMwv4eunwKBgFPXacXXok5bfUMq/c4jJmp4
VreipwaYlXw34B69RjUnhzXa9ZnVaYqGB6vn0kcFZIUUI6YA/KBiN66yDoyQuAHN
QcL3mwmyLfhwudQ8N7DLITkSEtrPvnxFBWWp4mIsYHxlbnc4ulTTXy5tHm8q8C5h
iA7CrudyyTCy/coVSNEhAoGABq8eAtFjnxXp8KOsSXNCjHBUHzWALXd+2v3Gn7Hj
fMOXa54kY+kn9NMi0C4w5+r9tDos87Rs6FaPwUU3RhpT6ZLanPdV5pI9UJDoKpXE
iIL/AUtMfN5Qsi4dHMPKAe+oT27jG3mJNZrnpvNsj4eSjja92sgXRMZ/IdWhQe7W
bZMCgYBTieTkOQKv5yqXtVlgU2HwAYrnq60y9Mnz/LwMTQrKm/oJu7Pv9P6ISLkG
BpBCZXvcsfF4nmCQuv3U3mfig4ubte3wN/6Xln+WZM4/t8KMS9bU8ye4NaIHm666
GCeH9q+NkgOk/a9nS2sOqUvcZKV9MiScIk37p5pAcLH0Agg6RQ==
-----END RSA PRIVATE KEY-----`,
		wantErr: false,
	},
	{
		name: "invalid public key",
		publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIIEoQIBAAKCAQBuCeEl1Gu4355usZGRnbmYj+NOhKwcam/BeCGeoOaeT5OJmZMy
c4o+iocR6rxj33hN2a2A+abnRT++gIsYRni6t/PDMRLrH+enAWi42GwizE5a6PE2
aoVChxCgBhOkgxDjPDcToBFwa5wx8Q6crJ95lijP3y3BIL3Y6m07ruQA5Yv1D/yI
-----END PUBLIC KEY-----`,
		privateKeyPem: `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBuCeEl1Gu4355usZGRnbmYj+NOhKwcam/BeCGeoOaeT5OJmZMy
c4o+iocR6rxj33hN2a2A+abnRT++gIsYRni6t/PDMRLrH+enAWi42GwizE5a6PE2
aoVChxCgBhOkgxDjPDcToBFwa5wx8Q6crJ95lijP3y3BIL3Y6m07ruQA5Yv1D/yI
-----END RSA PRIVATE KEY-----`,
		wantErr: true,
	},
}

func TestKeys(t *testing.T) {
	for _, test := range keysTestCases {
		if test.wantErr {
			continue
		}
		t.Run(fmt.Sprintf("%s: PrivateKey", test.name), func(t *testing.T) {
			privateKeyBytes := []byte(test.privateKeyPem)
			privateKey, err := ParsePrivateKeyFromPem(privateKeyBytes)
			if err != nil {
				t.Errorf("TestPrivateKey: ParsePrivateKeyFromPem encountered error: %s", err)
			}
			privateKeyPem := ConvertPrivateKeyToPem(privateKey)
			if !bytes.Equal(privateKeyPem, privateKeyBytes) {
				t.Errorf("TestPrivateKey: privateKeyBytes != privateKeyPem")
			}
		})
		/* BUG: need to fix this test
		t.Run(fmt.Sprintf("%s: PublicKey", test.name), func(t *testing.T) {
			publicKeyBytes := []byte(test.publicKeyPem)
			publicKey, err := ParsePublicKeyFromPem(publicKeyBytes)
			if err != nil {
				t.Errorf("TestPublicKey: ParsePublicKeyFromPem encountered error: %s", err)
			}
			publicKeyPem := ConvertPublicKeyToPem(publicKey)
			if !bytes.Equal(publicKeyPem, publicKeyBytes) {
				t.Errorf("TestPublicKey: publicKeyBytes != publicKeyPem")
			}
		})
		*/

	}
}

func TestJunkKeys(t *testing.T) {
	for _, test := range keysTestCases {
		if !test.wantErr {
			continue
		}
		t.Run(fmt.Sprintf("%s: PrivateKey", test.name), func(t *testing.T) {
			privateKeyBytes := []byte(test.privateKeyPem)
			_, err := ParsePrivateKeyFromPem(privateKeyBytes)
			if err == nil {
				t.Errorf("TestPrivateKey: ParsePrivateKeyFromPem should have encountered error")
			}
		})
		t.Run(fmt.Sprintf("%s: PublicKey", test.name), func(t *testing.T) {
			publicKeyBytes := []byte(test.publicKeyPem)
			_, err := ParsePublicKeyFromPem(publicKeyBytes)
			if err == nil {
				t.Errorf("TestPublicKey: ParsePublicKeyFromPem should have encountered error")
			}
		})
	}
}
