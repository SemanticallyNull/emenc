package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"syscall/js"
)

func main() {
	done := make(chan struct{}, 0)
	js.Global().Set("genEDKey", js.FuncOf(genEDKey))
	js.Global().Set("signED", js.FuncOf(signED))
	js.Global().Set("verifyED", js.FuncOf(verifyED))
	<-done
}

func genEDKey(this js.Value, args []js.Value) any {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return map[string]any{
		"pub": base64.RawURLEncoding.EncodeToString(pub),
		"pk":  base64.RawURLEncoding.EncodeToString(priv),
	}
}

func signED(this js.Value, args []js.Value) any {
	pk := args[0].String()
	input := args[1].String()

	p, err := base64.RawURLEncoding.DecodeString(pk)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return map[string]any{
		"signedMessage": base64.RawURLEncoding.EncodeToString(ed25519.Sign(p, []byte(input))),
	}
}

func verifyED(this js.Value, args []js.Value) any {
	pub := args[0].String()
	input := args[1].String()
	sig := args[2].String()

	p, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		return map[string]any{
			"valid": false,
		}
	}
	s, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return map[string]any{
			"valid": false,
		}
	}

	return map[string]any{
		"valid": ed25519.Verify(p, []byte(input), s),
	}
}
