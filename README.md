# Portshift Klar

Klar is a tool to analyze images stored in a private or public  Docker registry for security vulnerabilities using Grype.

## Binary installation

The simplest way is to download the latest release (for OSX and Linux) from https://github.com/Portshift/klar/releases/ and put the binary in a folder in your `PATH` (make sure it has execute permission).

## Installation from source code

Make sure you have Go language compiler installed and configured https://golang.org/doc/install

Then run

    go get github.com/Portshift/klar

make sure your Go binary folder is in your `PATH` (e.g. `export PATH=$PATH:/usr/local/go/bin`)


## Usage

Klar process returns if `0` if the number of detected high severity vulnerabilities in an image is less than or equal to a threshold (see below) and `1` if there were more. It will return `2` if an error has prevented the image from being analyzed.

Klar can be configured via the following environment variables:

* `GRYPE_ADDR` - address of Grype server.

* `SEVERITY_THRESHOLD` - severity level threshold, vulnerabilities with severity level higher than or equal to this threshold
will be outputted. Supported levels are `Unknown`, `Negligible`, `Low`, `Medium`, `High`, `Critical`, `Defcon1`.
Default is `Unknown`.
  
* `DOCKER_USER` - Docker registry account name.

* `DOCKER_PASSWORD` - Docker registry account password.

* `DOCKER_TOKEN` - Docker registry account token. (Can be used in place of `DOCKER_USER` and `DOCKER_PASSWORD`)

* `DOCKER_INSECURE` - Allow Klar to access registries with bad SSL certificates. Default is `false`.

* `DOCKER_TIMEOUT` - timeout in minutes when trying to fetch layers from a docker registry

* `DOCKER_PLATFORM_OS` - The operating system of the Docker image. Default is `linux`. This only needs to be set if the image specified references a Docker ManifestList instead of a usual manifest.

* `DOCKER_PLATFORM_ARCH` - The architecture the Docker image is optimized for. Default is `amd64`. This only needs to be set if the image specified references a Docker ManifestList instead of a usual manifest.

* `REGISTRY_INSECURE` - Allow Klar to access insecure registries (HTTP only). Default is `false`.

* `JSON_OUTPUT` - Output JSON, not plain text. Default is `false`.

* `FORMAT_OUTPUT` - Output format of the vulnerabilities. Supported formats are `standard`, `json`, `table`. Default is `standard`. If `JSON_OUTPUT` is set to true, this option is ignored.

* `WHITELIST_FILE` - Path to the YAML file with the CVE whitelist. Look at `whitelist-example.yaml` for the file format.

* `IGNORE_UNFIXED` - Do not count vulnerabilities without a fix towards the threshold

### Debug Output
You can enable more verbose output but setting `KLAR_TRACE` to true.
* run `export KLAR_TRACE=true` to persist between runs.

## Dockerized version

Klar can be dockerized. Go to `$GOPATH/src/github.com/Portshift/klar` and build Klar in project root. If you are on Linux:

    CGO_ENABLED=0 go build -a -installsuffix cgo .

If you are on Mac don't forget to build it for Linux:

    GOOS=linux go build .

To build Docker image run in the project root (replace `klar` with fully qualified name if you like):

    docker build -t klar .

## Amazon ECR support
There is no permanent username/password for Amazon ECR, the credentials must be retrived using `aws ecr get-login` and they are valid for 12 hours. Here is a sample script which may be used to provide Klar with ECR credentials:

    DOCKER_LOGIN=`aws ecr get-login --no-include-email`
    PASSWORD=`echo $DOCKER_LOGIN | cut -d' ' -f6`
    REGISTRY=`echo $DOCKER_LOGIN | cut -d' ' -f7 | sed "s/https:\/\///"`
    DOCKER_USER=AWS DOCKER_PASSWORD=${PASSWORD} ./klar ${REGISTRY}/my-image

## Google GCR support
For authentication against GCR (Google Cloud Registry), the easiest way is to use the [application default credentials](https://developers.google.com/identity/protocols/application-default-credentials). These only work when running Klar from GCP. The only requirement is the Google Cloud SDK.

    DOCKER_USER=oauth2accesstoken
    DOCKER_PASSWORD="$(gcloud auth application-default print-access-token)"

With Docker:

    DOCKER_USER=oauth2accesstoken
    DOCKER_PASSWORD="$(docker run --rm google/cloud-sdk:alpine gcloud auth application-default print-access-token)"
