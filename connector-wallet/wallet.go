/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package wallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/apache/incubator-answer-plugins/connector-wallet/i18n"
	"github.com/apache/incubator-answer/plugin"
	"github.com/ethereum/go-ethereum/crypto"
)

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	SignatureMethod string `json:"signature_method"`
}

func init() {
	plugin.Register(&Connector{
		Config: &ConnectorConfig{},
	})
}

// Implement the Base interface
func (g *Connector) Info() plugin.Info {
	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    "wallet_connector",
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      "i-Luicfer",
		Version:     "0.0.1",
		Link:        "https://github.com/apache/incubator-answer-plugins/tree/main/connector-wallet",
	}
}

// Implement the Connector plugin interface
func (g *Connector) ConnectorLogoSVG() string {
	return `PHN2ZyB0PSIxNzE3ODM1NzkwNTM1IiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjMyNjU3IiB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCI+PHBhdGggZD0iTTgxMC42NjY2NjcgMjk4LjY2NjY2N2gtNDIuNjY2NjY3VjI1NmExMjggMTI4IDAgMCAwLTEyOC0xMjhIMjEzLjMzMzMzM2ExMjggMTI4IDAgMCAwLTEyOCAxMjh2NTEyYTEyOCAxMjggMCAwIDAgMTI4IDEyOGg1OTcuMzMzMzM0YTEyOCAxMjggMCAwIDAgMTI4LTEyOHYtMzQxLjMzMzMzM2ExMjggMTI4IDAgMCAwLTEyOC0xMjh6TTIxMy4zMzMzMzMgMjEzLjMzMzMzM2g0MjYuNjY2NjY3YTQyLjY2NjY2NyA0Mi42NjY2NjcgMCAwIDEgNDIuNjY2NjY3IDQyLjY2NjY2N3Y0Mi42NjY2NjdIMjEzLjMzMzMzM2E0Mi42NjY2NjcgNDIuNjY2NjY3IDAgMCAxIDAtODUuMzMzMzM0eiBtNjQwIDQyNi42NjY2NjdoLTQyLjY2NjY2NmE0Mi42NjY2NjcgNDIuNjY2NjY3IDAgMCAxIDAtODUuMzMzMzMzaDQyLjY2NjY2NnogbTAtMTcwLjY2NjY2N2gtNDIuNjY2NjY2YTEyOCAxMjggMCAwIDAgMCAyNTZoNDIuNjY2NjY2djQyLjY2NjY2N2E0Mi42NjY2NjcgNDIuNjY2NjY3IDAgMCAxLTQyLjY2NjY2NiA0Mi42NjY2NjdIMjEzLjMzMzMzM2E0Mi42NjY2NjcgNDIuNjY2NjY3IDAgMCAxLTQyLjY2NjY2Ni00Mi42NjY2NjdWMzc2Ljc0NjY2N0ExMjggMTI4IDAgMCAwIDIxMy4zMzMzMzMgMzg0aDU5Ny4zMzMzMzRhNDIuNjY2NjY3IDQyLjY2NjY2NyAwIDAgMSA0Mi42NjY2NjYgNDIuNjY2NjY3eiIgcC1pZD0iMzI2NTgiPjwvcGF0aD48L3N2Zz4=`
}

func (g *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (g *Connector) ConnectorSlugName() string {
	return "wallet"
}

func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	// fmt.Printf("receiverURL: (%s) \n", receiverURL)
	// redirectURL = "https://www.baidu.com/"
	redirectURL = ""
	// fmt.Printf("redirectURL: (%s) \n", redirectURL)
	return ""
}

func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	message := ctx.Query("message")
	signature := ctx.Query("signature")
	address := ctx.Query("address")
	pp("message", message)
	pp("signature", signature)
	pp("address", address)
	if !verifySignature(message, signature, address) {
		return userInfo, fmt.Errorf("Signature verification failed")
	}
	userInfo.ExternalID = address
	return userInfo, nil
}

// Implement the Translator interface
func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "signature_method",
			Type:        plugin.ConfigTypeSelect,
			Title:       plugin.MakeTranslator(i18n.ConfigSignatureMethodTitle),
			Description: plugin.MakeTranslator(i18n.ConfigSignatureMethodDescription),
			Required:    true,
			UIOptions:   plugin.ConfigFieldUIOptions{},
			Value:       g.Config.SignatureMethod,
			Options: []plugin.ConfigFieldOption{
				{
					Value: "nonce",
					Label: plugin.MakeTranslator(i18n.ConfigSignatureMethodNonce),
				},
				{
					Value: "random",
					Label: plugin.MakeTranslator(i18n.ConfigSignatureMethodRandom),
				},
				{
					Value: "timestamp",
					Label: plugin.MakeTranslator(i18n.ConfigSignatureMethodTimestamp),
				},
			},
		},
	}
}

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	_ = json.Unmarshal(config, c)
	g.Config = c
	return nil
}

// 绑定电子邮箱
func (g *Connector) guaranteeEmail(email string, accessToken string) string {
	return email
}

func verifySignature(message, signature, address string) bool {
	sig, err := hex.DecodeString(signature[2:])
	if err != nil {
		log.Println("Failed to decode signature:", err)
		return false
	}
	prefix := "\x19Ethereum Signed Message:\n" + fmt.Sprintf("%d", len(message))
	msg := []byte(prefix + message)
	msgHash := crypto.Keccak256Hash(msg)
	if sig[64] != 27 && sig[64] != 28 {
		return false
	}
	sig[64] -= 27
	pubKey, err := crypto.SigToPub(msgHash.Bytes(), sig)
	if err != nil {
		log.Println("Failed to get public key from signature:", err)
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	return strings.ToLower(recoveredAddr.Hex()) == strings.ToLower(address)
}

func pp(params ...interface{}) {
	for index, param := range params {
		fmt.Printf("index (%d) param (%v) \n", index, param)
	}
}

// func pv(fn string, param interface{}) {
// 	fmt.Printf("index (%s) param (%+v) \n", fn, param)
// }

// func pj(fn string, param interface{}) {
// 	result, _ := json.Marshal(param)
// 	fmt.Printf("index (%s) param (%s) \n", fn, result)
// }
