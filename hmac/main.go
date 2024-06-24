package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	maxInputBuffer = 1024
)

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "persistent Handle where we saved the key")
	hmacKey          = flag.String("hmacKey", "", "the hmackey")
	bucketName       = flag.String("bucketName", "", "Bucket")
	objectName       = flag.String("objectName", "somefile.txt", "object")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("error: can't open TPM  %v\n", err)
		return
	}
	defer func() {
		rwc.Close()
	}()
	rwr := transport.FromReadWriter(rwc)

	// recreate the primary created by
	// tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt"
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// load the key from the handle
	keyHandle := tpm2.TPMHandle(tpm2.TPMHandle(*persistentHandle))
	keyPublic, err := tpm2.ReadPublic{
		ObjectHandle: keyHandle,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't read public hmac key name %v", err)
	}

	verb := "GET"
	resource := fmt.Sprintf("/%s/%s", *bucketName, *objectName)

	contentMD5 := ""
	contentType := ""
	expiration := strconv.FormatInt((time.Now().Add(time.Duration(60 * time.Second)).Unix()), 10)
	signatureString := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", verb, contentMD5, contentType, expiration, resource)

	// note, we need to use sha1 ..
	signedString, err := hmac(rwr, []byte(signatureString), keyHandle, keyPublic.Name, tpm2.TPM2BAuth{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not sign string  %v\n", err)
		os.Exit(1)
	}

	b64signedString := url.QueryEscape(base64.StdEncoding.EncodeToString(signedString))

	signedURL := fmt.Sprintf("https://storage.googleapis.com/%s/%s?GoogleAccessId=%s&Expires=%s&Signature=%s", *bucketName, *objectName, *hmacKey, expiration, b64signedString)

	fmt.Printf("SignedURL %s\n", signedURL)

	resp, err := http.Get(signedURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could get object  %v\n", err)
		os.Exit(1)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could get object  %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Object Content: %s\n", string(body))

}

func hmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, objAuth tpm2.TPM2BAuth) ([]byte, error) {

	// using sha1
	sas, sasCloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA1, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = sasCloser()
	}()

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: sas.Handle(),
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: objHandle,
			Name:   objName,
			Auth:   sas,
		},
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objName,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}
