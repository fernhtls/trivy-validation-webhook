# Dynimac admission controller - image inspection (trivy)

This is more of an example on how to develope a `go` valiation webhook using `trivy`, and blocking the creation of pods that don't pass a severity criteria.

The severity criteria has a [default settings](https://github.com/fernhtls//filename#16), but it can ve overwritten by env vars.

The env var pattern to replace should be `TRIVY_<SEVERITY>_THRESHOLD`, and severity being `CRITICAL`, `HIGH` and others.

The handler will then run `trivy`, get the results and compare the total number of CVEs and its severities agains the threshold, and then send the Admission reponse as passing or not the check.

I'm not including any custom auth for registries, as if you're using an image from a private registry you might need to pass proper credntials to the app.

See this whole repo and code as more of an exercise, and probably one way of doing some customs checks, but there are other solutions able to do the same from `trivy` itself, and others like `kyverno`, being this last one a more complex but complete solution with several easy to define policies for dynamic admission controllers.

The steps to make it all work are:

1. Generate all the CA Bundle keys needed (admission webhooks only work with TLS endpoints and so you need to generate ca certs).
    1. Certs here are all self-signed, **but don't use the same process for production**, use a cert-manager and proper expiration and rotation of the certs.
    2. Steps [here](#generating-ca-bundle-certs).
2. Build the image and share with your cluster.
    1. I'm using podman, so I could build the image locally and load to the cluster using or the podman app, or through command.
3. Deploy all resources within the dir [k8s-yamls](./k8s-yamls).
    1. A TLS secret needs to be created before deploying all resouces:
    ```bash
    kubectl -n default create secret tls trivy-webhook-tls --cert=./ca-certs/server.crt --key=./ca-certs/server.keys
    ```
    2. Deploy all resouces to the `default` namespace, and `default` is whilisted from checks.
4. I'll describe some tests [here](#checking-the-validation-webhook).

## Generating CA Bundle certs

1. Generate CA private key:

Create CA private key:

```bash
openssl genrsa -out ca.key 2048
```

Create self-signed CA certificate (valid 10y):

```bash
openssl req -x509 -new -nodes -key ca.key -subj "/CN=trivy-webhook-ca" -days 3650 -out ca.crt
```

2. Create server key and CSR for the webhook service:

Server private key:

```bash
openssl genrsa -out server.key 2048
```

Create CSR with SAN for Kubernetes service DNS names:

```bash
cat > server.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = trivy-webhook.default.svc

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:trivy-webhook.default.svc,DNS:trivy-webhook,DNS:trivy-webhook.default,DNS:trivy-webhook.default.svc.cluster
EOF
```

```bash
openssl req -new -key server.key -out server.csr -config server.cnf
```

3. Sign server CSR with the CA:

```bash
cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName = DNS:trivy-webhook.default.svc,DNS:trivy-webhook,DNS:trivy-webhook.default,DNS:trivy-webhook.default.svc.cluster
EOF
```

```bash
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extfile server.ext
```

4. Create the CA bundle (base64-encoded) for Kubernetes:

```bash
cat ca.crt | base64 | tr -d '\n' > ca.crt.base64
```

5. Create the TLS secret (Will be mounted for the deployment):

```bash
kubectl -n default create secret tls trivy-webhook-tls --cert=./ca-certs/server.crt --key=./ca-certs/server.key
```

## Checking the validation webhook

I'm creating the `trivy-webhook` on the `default` namespace, so the namespace is excluded from the webhook triggers.

For testing we can create a new namespace, for example `apps`:

```bash
kubectl create ns apps
```

And then we can try and create pod with certain images.

A pod with the `ubuntu:latest` image does not have much CVEs, just LOW severity ones, so the pod should be created without any issues.


```bash
kubectl -n apps run ubuntu-test --image=ubuntu:latest -- sleep 600
```

The creation should pass wihout any issues and you can inspect the logs on the `trivy-webhook` the logs the severity checks and it went.

But let's check the logs on our trivy pods to see what happend and which CVEs do we have on this image:

```bash
kubectl logs -f trivy-webhook-7dc78c4567-c2z2g
```

```bash
2026/04/03 08:10:03 threshold settings : map[CRITICAL:0 HIGH:5 LOW:10]
2026/04/03 08:10:03 starting webhook
2026/04/03 08:11:52 Validating Pod: ubuntu-test in Namespace: apps
2026/04/03 08:12:01 Validating Pod: ubuntu-test in Namespace: apps / Trivy results: {[{[{CVE-2024-2236 LOW} {CVE-2024-56433 LOW} {CVE-2024-56433 LOW}]}]}
2026/04/03 08:12:01 Validating Pod: ubuntu-test in Namespace apps: / image ubuntu:latest pass the severity criteria - criteria: map[CRITICAL:0 HIGH:5 LOW:10] / result: map[LOW:3]
```
We can see that the image has some `LOW` severity CVEs, and it passes the test as our criteria checks for max `10` `LOW`.

Now the same test with a pod, but with a image with `HIGH` CVEs and a `CRTIICAL` one:

```bash
kubectl -n apps run postgres-test --image=postgres:14.22-trixie
```

This apps needs other input arguments as the root / admin password to be used on postgres, but the pod won't have the chance to even get created:

```bash
kubectl -n apps run postgres-test --image=postgres:14.22-trixie
Error from server: admission webhook "trivy-validation.example.com" denied the request: image does not comply with security scan criteria. Criteria: map[CRITICAL:0 HIGH:5 LOW:10] / Results: map[CRITICAL:1 HIGH:22 LOW:125]
```

Let's try a new deployment with the same image and see if the webhook blocks it:

```bash
kubectl -n apps create deploy postgres-test-dep --image=postgres:14.22-trixie --replicas=2
```

Even after sometime we can see that we don't have `READY` pods:

```bash
kubectl -n apps get deploy -o wide -w
NAME                READY   UP-TO-DATE   AVAILABLE   AGE   CONTAINERS   IMAGES                  SELECTOR
postgres-test-dep   0/2     0            0           23s   postgres     postgres:14.22-trixie   app=postgres-test-dep
```

Let's check events on the `apps` namespace:

```bash
kubectl -n apps get events
LAST SEEN   TYPE      REASON              OBJECT                                    MESSAGE
34s         Warning   FailedCreate        replicaset/postgres-test-dep-75968dc668   Error creating: admission webhook "trivy-validation.example.com" denied the request: image does not comply with security scan criteria. Criteria: map[CRITICAL:0 HIGH:5 LOW:10] / Results: map[CRITICAL:1 HIGH:22 LOW:125]

```

We can see that the image don't pass the check criteria, so the replicaset can't create pods.

The `CRITICAL` CVE for this image is `CVE-2025-68121`: 

```bash
trivy image postgres:14.22-trixie
...
┌─────────┬────────────────┬──────────┬────────┬───────────────────┬──────────────────────────────┬──────────────────────────────────────────────────────────────┐
│ Library │ Vulnerability  │ Severity │ Status │ Installed Version │        Fixed Version         │                            Title                             │
├─────────┼────────────────┼──────────┼────────┼───────────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ stdlib  │ CVE-2025-68121 │ CRITICAL │ fixed  │ v1.24.6           │ 1.24.13, 1.25.7, 1.26.0-rc.3 │ crypto/tls: Unexpected session resumption in crypto/tls      │
│         │                │          │        │                   │                              │ https://avd.aquasec.com/nvd/cve-2025-68121                   │
...
```
