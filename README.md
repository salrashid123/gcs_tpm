# GCS signedURLs  with Trusted Platform Module

Samples in golang that enables the following where the private key or hmac secret is embedded with a TPM (Trusted Platform Module)

1. HMAC SignedURLs:  
   - Import a GCS HMAC secret and use it to generate a SignedURL.
     See [GCS HMAC Signed URL](https://blog.salrashid.dev/articles/2018/gcs_hmac/)
2. RSA SignedURL: 
   - Generate a service account json file
   - Import that key into ta TPM
   - Generate SignedURL using TPM
   - Access GCS Object

---

>> this repository is not supported by Google


## Setup

Create GCS Bucket, object and Service Account and HMAC key to test with

```bash
export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format='value(projectNumber)'`

# create a gcs bucket and object
gcloud storage buckets create gs://$PROJECT_ID-bucket
echo -n "some text" > somefile.txt
gcloud storage cp somefile.txt gs://$PROJECT_ID-bucket

# create a service account that has access to a bucket
gcloud iam service-accounts create tpm-svc-account --project $PROJECT_ID
gcloud iam service-accounts keys list --iam-account tpm-svc-account@$PROJECT_ID.iam.gserviceaccount.com

# allow the service account access to the bucket
gcloud storage buckets add-iam-policy-binding  gs://$PROJECT_ID-bucket --member="serviceAccount:tpm-svc-account@$PROJECT_ID.iam.gserviceaccount.com" --role="roles/storage.objectViewer"

# remember the hmac key and secret
gcloud storage hmac create tpm-svc-account@$PROJECT_ID.iam.gserviceaccount.com 
	accessId: GOOG1EV3Z4JLVW3XLMDX52PGIWFXAW7IM5VXDP-redacted
	secret: WE8gT3r3PlSSgaQGs5-redacted
```

You can use a system with a real tpm but if all you just want to test with a software tpm (`swtpm`):

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
```

then install [tpm2_tools](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/)

```bash
$ export TPM2TOOLS_TCTI="swtpm:port=2321"
$ tpm2_pcrread sha256:0,23
```

### HMAC

Embed the HMAC key into the TPM.  You can use golang but here we're using `tpm2_tools`.

We are going to import the hmac key using this procedure: [hmac_import](https://github.com/salrashid123/tpm2/tree/master/hmac_import)

```bash
export HMAC_SECRET="WE8gT3r3PlSSgaQGs5-redacted"
echo -n $HMAC_SECRET > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)
echo $hexkey

tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt"

## note we're using sha1 for the actual hmac part
tpm2_import -C primary.ctx -G hmac:sha1 -g sha256 -i hmac.key -u hmac.pub -r hmac.priv
tpm2_flushcontext -t
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx

# evict it to handle 0x81008001
tpm2_evictcontrol -C o -c hmac.ctx 0x81008001 
tpm2_flushcontext -t
```

At this point the hmac key is embedded into the TPM and you can also set TPM Policies that govern how to access the key (eg, passwordPolicy, PCR Policy, etc)

to run,

```bash
## if using the swtpm:
go run hmac/main.go --tpm-path="127.0.0.1:2321" \
   --persistentHandle=0x81008001 \
   --hmacKey="GOOG1EV3Z4JLVW3XLMDX52PGIWFXAW7IM5VXDPB2NB2MAVJX5PYCGPHKZEVJ6" \
   --bucketName=$PROJECT_ID-bucket --objectName=somefile.txt
```

![images/hmac.png](images/hmac.png)

### Service Account RSA

To create a TPM-embedded signed url, you first need to associate a TPM object with a service account key.

There are several ways to do that described [Usage TpmTokenSource](https://github.com/salrashid123/oauth2#usage-tpmtokensource)

but for simplicity, we're just going to do a variation of option (A)

```bash
## first extract the key for import
gcloud iam service-accounts keys create tpm-svc-account.json --iam-account=tpm-svc-account@$PROJECT_ID.iam.gserviceaccount.com
cat tpm-svc-account.json | jq -r '.private_key' > /tmp/f.json
openssl rsa -in /tmp/f.json -out /tmp/key_rsa.pem 

tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt"

# import
tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256 -i /tmp/key_rsa.pem -u key.pub -r key.prv
tpm2_flushcontext  -t
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx 
tpm2_flushcontext  -t

# evict it to handle 0x81008002
tpm2_evictcontrol -C o -c key.ctx 0x81008002 
tpm2_flushcontext -t
```

Now run:

```bash
## if using the swtpm:
go run svcaccount/main.go --tpm-path="127.0.0.1:2321" \
   --persistentHandle=0x81008002 \
   --serviceAccountEmail="tpm-sa@$PROJECT_ID.iam.gserviceaccount.com" \
   --bucketName=$PROJECT_ID-bucket --objectName=somefile.txt
```

with SignedURL
![images/signed.png](images/signed.png)

---


## References

- [AWS v4 Signer for embedding Access Secrets to PKCS11 and TPMs](https://github.com/salrashid123/aws_hmac)

- [TPM TokenSource for GoogleCloud](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
  golang `TokenSource` which derives GCP Oauth2 and JWTAccessTokens from a TPM for use with GCP Client libraries
- [TPM AccessTokens using Openssl TPM library](https://github.com/salrashid123/tpm2_evp_sign_decrypt)
  Create oauth2 and jwtaccess tokens using TPM support with openssl
- [TPM based golang crypto.Signer](https://github.com/salrashid123/signer)
- [Importing an external RSA key](https://github.com/salrashid123/tpm2/tree/master/tpm_import_external_rsa)

- [Signed URLs Options](https://cloud.google.com/storage/docs/access-control/signed-urls#types)
- [GCS HMAC Keys](https://cloud.google.com/storage/docs/authentication/hmackeys)

