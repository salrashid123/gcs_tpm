package main

import (
	"crypto"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
)

const ()

var (
	tpmPath             = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle    = flag.Uint("persistentHandle", 0x81008002, "persistent Handle where we saved the key")
	bucketName          = flag.String("bucketName", "core-eso-bucket", "Bucket")
	objectName          = flag.String("objectName", "somefile.txt", "object")
	serviceAccountEmail = flag.String("serviceAccountEmail", "tpm-sa@core-eso.iam.gserviceaccount.com", "ServiceAccountEmail")
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
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(*persistentHandle),
			Name:   pub.Name,
		},
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	expires := time.Now().Add(time.Minute * 10)

	s, err := storage.SignedURL(*bucketName, *objectName, &storage.SignedURLOptions{
		Scheme:         storage.SigningSchemeV4,
		GoogleAccessID: *serviceAccountEmail,
		SignBytes: func(b []byte) ([]byte, error) {
			opts := crypto.SHA256
			hash := sha256.Sum256(b)
			return r.Sign(rwc, hash[:], opts)
		},
		Method:  "GET",
		Expires: expires,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting object %s\n", err)
		return
	}
	fmt.Printf("SignedURL: %s\n", s)

	resp, err := http.Get(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting object %s\n", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	fmt.Printf("SignedURL Response :\n%s\n", string(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting object %s\n", err)
		return
	}

}
