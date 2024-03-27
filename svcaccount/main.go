package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/google/go-tpm-tools/client"
	"google.golang.org/api/option"

	"cloud.google.com/go/storage"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/oauth2/tpm"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	primaryHandle = flag.String("primaryHandle", "primary.bin", "Handle to the primary")
	keyHandle     = flag.String("keyHandle", "key.bin", "Handle to the privateKey")
	flush         = flag.String("flush", "all", "Flush existing handles")
	mode          = flag.String("mode", "", "Mode:  gencert|genurl|useclient")
	bucketName    = flag.String("bucketName", "mineral-minutia-820-bucket", "Bucket")
	objectName    = flag.String("objectName", "somefile.txt", "object")
	x509certFile  = flag.String("x509certFile", "x509cert.pem", "x509 certificate ")
	cn            = flag.String("cn", "OURServiceAccountName@PROJECT_ID.iam.gserviceaccount.com", "Common Name for the certificate ")
	keyId         = flag.String("keyID", "dde6c06d9a0c58d1437db8d8a91c979b7ad36945", "KeyID for the serviceAccount")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	rsaKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()

	if *mode == "gencert" {
		rwc, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
				os.Exit(1)
			}
		}()

		totalHandles := 0
		for _, handleType := range handleNames[*flush] {
			handles, err := client.Handles(rwc, handleType)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
				os.Exit(1)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
					os.Exit(1)
				}
				fmt.Printf("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}

		var kk *client.Key
		var kh tpmutil.Handle
		// A) either use the AK

		// a1) Get Attestation Key
		// AttestationKeyRSA generates and loads a key from AKTemplateRSA in the ***Owner*** hierarchy.
		// kk, err = client.AttestationKeyRSA(rwc)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "can't AK %q: %v", tpmPath, err)
		// 	os.Exit(1)
		// }

		// a2) only if on a GCE instance
		// if you use the AK, the public key will be the same as
		// gcloud compute instances get-shielded-identity tpm-test --zone us-central1-a --format="value(signingKey.ekPub)"
		// kk, err = client.GceAttestationKeyRSA(rwc)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "can't AK %q: %v", tpmPath, err)
		// 	os.Exit(1)
		// }

		// get the keyhandle
		// kh = kk.Handle()
		// defer tpm2.FlushContext(rwc, kh)

		// B) or Create a new Key
		pcrList := []int{0}
		pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

		pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, pkh)

		pkhBytes, err := tpm2.ContextSave(rwc, pkh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for pkh %v\n", err)
			os.Exit(1)
		}

		err = os.WriteFile(*primaryHandle, pkhBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
			os.Exit(1)
		}

		privInternal, pubArea, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, rsaKeyParams)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
			os.Exit(1)
		}
		// get the key handle
		kh, _, err = tpm2.Load(rwc, pkh, defaultPassword, pubArea, privInternal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, kh)

		// save the key handle to disk

		ekhBytes, err := tpm2.ContextSave(rwc, kh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for ekh %v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(*keyHandle, ekhBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for ekh%v\n", err)
			os.Exit(1)
		}

		fmt.Printf("======= Key persisted ========\n")

		// Either way, load the Key

		kk, err = client.NewCachedKey(rwc, tpm2.HandleOwner, rsaKeyParams, kh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't NewCachedKey %q: %v", tpmPath, err)
			os.Exit(1)
		}

		pubKey := kk.PublicKey().(*rsa.PublicKey)
		akBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR:  could not get MarshalPKIXPublicKey: %v", err)
			os.Exit(1)
		}
		akPubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: akBytes,
			},
		)

		fmt.Printf("Signing Public Key: \n%s\n", akPubPEM)

		s, err := kk.GetSigner()
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't getSigner %q: %v", tpmPath, err)
			os.Exit(1)
		}

		var csrTemplate = x509.CertificateRequest{
			Subject: pkix.Name{
				Organization:       []string{"Acme Co"},
				OrganizationalUnit: []string{"Enterprise"},
				Locality:           []string{"Mountain View"},
				Province:           []string{"California"},
				Country:            []string{"US"},
				CommonName:         *cn,
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
		}
		// step: generate the csr request
		csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't create CSR %v", err)
			os.Exit(1)
		}
		csr := pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
		})

		fmt.Printf("CSR: \n%s\n", csr)

		fmt.Printf("======= Creating self-signed Certificate ========\n")

		var notBefore time.Time
		notBefore = time.Now()

		notAfter := notBefore.Add(time.Hour * 24 * 365)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate serial number: %s", err)
			os.Exit(1)
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization:       []string{"Acme Co"},
				OrganizationalUnit: []string{"Enterprise"},
				Locality:           []string{"Mountain View"},
				Province:           []string{"California"},
				Country:            []string{"US"},
				CommonName:         *cn,
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			DNSNames:              []string{*cn},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, kk.PublicKey(), s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create certificate: %s\n", err)
			os.Exit(1)
		}
		certOut, err := os.Create(*x509certFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open %s for writing: %s", *x509certFile, err)
			os.Exit(1)
		}
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write data to %s: %s", *x509certFile, err)
			os.Exit(1)
		}
		if err := certOut.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing %s  %s", *x509certFile, err)
			os.Exit(1)
		}

		cert := pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: derBytes,
		})

		fmt.Printf("CERTIFICATE: \n%s\n", cert)

		fmt.Fprintf(os.Stderr, "wrote %s\n", *x509certFile)
	} else if *mode == "genurl" {

		rwc, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
				os.Exit(1)
			}
		}()

		totalHandles := 0
		for _, handleType := range handleNames[*flush] {
			handles, err := client.Handles(rwc, handleType)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
				os.Exit(1)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
					os.Exit(1)
				}
				fmt.Printf("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}

		khBytes, err := os.ReadFile(*keyHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextLoad read file for kh: %v", err)
			os.Exit(1)
		}
		kh, err := tpm2.ContextLoad(rwc, khBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextLoad failed for kh: %v", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, kh)

		k, err := client.NewCachedKey(rwc, tpm2.HandleOwner, rsaKeyParams, kh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldnot load CachedKey: %v", err)
			os.Exit(1)
		}

		si, err := k.GetSigner()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldnot get Signer: %v", err)
			os.Exit(1)
		}

		expires := time.Now().Add(time.Minute * 10)

		s, err := storage.SignedURL(*bucketName, *objectName, &storage.SignedURLOptions{
			Scheme:         storage.SigningSchemeV4,
			GoogleAccessID: *cn,
			SignBytes: func(b []byte) ([]byte, error) {
				opts := crypto.SHA256
				hash := sha256.Sum256(b)
				return si.Sign(rwc, hash[:], opts)
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
	} else if *mode == "useclient" {
		rwc, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
				os.Exit(1)
			}
		}()

		khBytes, err := os.ReadFile(*keyHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextLoad read file for kh: %v", err)
			os.Exit(1)
		}
		kh, err := tpm2.ContextLoad(rwc, khBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextLoad failed for kh: %v", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, kh)

		k, err := client.NewCachedKey(rwc, tpm2.HandleOwner, rsaKeyParams, kh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldnot load CachedKey: %v", err)
			os.Exit(1)
		}

		ts, err := sal.TpmTokenSource(
			&sal.TpmTokenConfig{
				TPMDevice: rwc,
				Email:     *cn,
				//KeyId:         *keyId,
				Key:           k,
				UseOauthToken: true,
			},
		)

		ctx := context.Background()
		storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting client %s\n", err)
			return
		}
		bkt := storageClient.Bucket(*bucketName)
		obj := bkt.Object(*objectName)
		r, err := obj.NewReader(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading object %s\n", err)
			return
		}
		fmt.Println()
		defer r.Close()
		if _, err := io.Copy(os.Stdout, r); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing writer %s\n", err)
			return
		}
		fmt.Println()
	}

}
