package encoder

import (
	"fmt"
	"github.com/y1nglamore/encoder/codec"
	"log"
)

func main() {
	fmt.Println("=== Base64 Encode / Decode Demo ===")
	b64Encoded := codec.EncodeBase64([]byte("Hello, Gopher!"))
	fmt.Println("Base64 Encoded:", b64Encoded)
	b64Decoded, _ := codec.DecodeBase64(b64Encoded)
	fmt.Println("Base64 Decoded:", string(b64Decoded))

	fmt.Println("\n=== Hex Encode / Decode Demo ===")
	hexEncoded := codec.EncodeHex([]byte("Hello, Hex!"))
	fmt.Println("Hex Encoded:", hexEncoded)
	hexDecoded, _ := codec.DecodeHex(hexEncoded)
	fmt.Println("Hex Decoded:", string(hexDecoded))

	fmt.Println("\n=== MD5 / SHA256 Hash Demo ===")
	md5Hash := codec.MD5Hash([]byte("secret"))
	sha256Hash := codec.SHA256Hash([]byte("secret"))
	fmt.Println("MD5 Hash:", md5Hash)
	fmt.Println("SHA256 Hash:", sha256Hash)

	fmt.Println("\n=== AES Encrypt / Decrypt Demo ===")
	key := []byte("0123456789ABCDEF") // 16字节
	plaintext := []byte("This is a secret message")
	aesCipher, err := codec.EncryptAES(plaintext, key)
	if err != nil {
		log.Fatalln("AES Encrypt Error:", err)
	}
	fmt.Println("AES Cipher (Base64):", codec.EncodeBase64(aesCipher))
	aesDecrypted, err := codec.DecryptAES(aesCipher, key)
	if err != nil {
		log.Fatalln("AES Decrypt Error:", err)
	}
	fmt.Println("AES Decrypted:", string(aesDecrypted))

	fmt.Println("\n=== RSA Encrypt / Decrypt Demo ===")
	privKey, pubKey, err := codec.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalln("GenerateRSAKeyPair Error:", err)
	}
	rsaCipher, err := codec.EncryptRSA(pubKey, []byte("RSA Secret"))
	if err != nil {
		log.Fatalln("RSA Encrypt Error:", err)
	}
	rsaDecrypted, err := codec.DecryptRSA(privKey, rsaCipher)
	if err != nil {
		log.Fatalln("RSA Decrypt Error:", err)
	}
	fmt.Println("RSA Original:", "RSA Secret")
	fmt.Println("RSA Decrypted:", string(rsaDecrypted))

}
