package codec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"
)

// EncodeBase64 对字节数据进行 Base64 编码
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 对 Base64 编码字符串进行解码
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeHex 对字节数据进行 Hex 编码
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex 对 Hex 编码字符串进行解码
func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// MD5Hash 计算 MD5 哈希值
func MD5Hash(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Hash 计算 SHA256 哈希值
func SHA256Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// EncryptAES 使用 AES-CBC 模式进行加密（示例）
func EncryptAES(plaintext, key []byte) ([]byte, error) {
	// key 长度一般是 16, 24, 32 字节，对应 AES-128, AES-192, AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// IV 向量长度与分组长度相同
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 使用 CBC
	mode := cipher.NewCBCEncrypter(block, iv)

	// 明文长度需要对齐到 blockSize 的倍数
	paddingSize := aes.BlockSize - len(plaintext)%aes.BlockSize
	padding := make([]byte, paddingSize)
	copy(padding, strings.Repeat("\x00", paddingSize))
	plaintext = append(plaintext, padding...)

	ciphertext := make([]byte, len(plaintext))

	// 加密
	mode.CryptBlocks(ciphertext, plaintext)

	// 将 iv 和 ciphertext 拼接返回
	return append(iv, ciphertext...), nil
}

// DecryptAES 使用 AES-CBC 模式进行解密（示例）
func DecryptAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// 拆分前 16 字节作为 IV
	iv := ciphertext[:aes.BlockSize]
	ciphertextData := ciphertext[aes.BlockSize:]

	if len(ciphertextData)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertextData))
	mode.CryptBlocks(decrypted, ciphertextData)

	// 去除末尾填充的 \x00
	decrypted = StripNullPadding(decrypted)

	return decrypted, nil
}

// StripNullPadding 去除末尾的 \x00 填充
func StripNullPadding(data []byte) []byte {
	return []byte(strings.TrimRight(string(data), "\x00"))
}

// GenerateRSAKeyPair 生成 RSA 私钥、公钥（示例）
func GenerateRSAKeyPair(bits int) (privateKey []byte, publicKey []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	// X.509 PKCS#1
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)

	return privBytes, pubBytes, nil
}

// EncryptRSA 使用公钥进行加密（示例）
func EncryptRSA(pubKey []byte, plaintext []byte) ([]byte, error) {
	publicKey, err := x509.ParsePKCS1PublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
}

// DecryptRSA 使用私钥进行解密（示例）
func DecryptRSA(privKey []byte, ciphertext []byte) ([]byte, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}

// SaveToFile 将字节数据写入文件
func SaveToFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0600)
}

// LoadFromFile 从文件读取字节数据
func LoadFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func Base32(cmd string, t string) (string, error) {

	if t == "encode" {
		command := exec.Command("sh", "-c", cmd)

		var outBuf, errBuf bytes.Buffer
		command.Stdout = &outBuf
		command.Stderr = &errBuf

		err := command.Run()
		output := outBuf.String() + errBuf.String()
		if err != nil {
			return output, err
		}

		return output, nil
	}
	return "", errors.New("invalid command")

}
