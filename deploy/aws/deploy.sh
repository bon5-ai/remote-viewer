#!/usr/bin/env bash
# Deploy deploy/aws/cloudfront.yaml with your own AWS credentials.
#
#   deploy/aws/deploy.sh STACK ORIGIN_HOST [ORIGIN_PORT] [CUSTOM_DOMAIN ACM_CERT_ARN_IN_US_EAST_1]
#
#   deploy/aws/deploy.sh remote-viewer my-box.my-tailnet.ts.net 8443
#   deploy/aws/deploy.sh remote-viewer my-box.my-tailnet.ts.net 8443 term.example.com arn:aws:acm:us-east-1:...
#
# The origin secret is generated once into $SECRET_FILE (mode 0600) and handed to
# CloudFormation from a temporary 0600 parameters file, so it is never typed, echoed, or
# put on a command line. Point the gate's proxy_secret_file at the same file.
# Uses whatever AWS profile and region your environment selects (AWS_PROFILE, AWS_REGION).
set -euo pipefail

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 2 ] || usage

STACK="$1"
ORIGIN="$2"
PORT="${3:-443}"
DOMAIN="${4:-}"
CERT="${5:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SECRET_FILE="${SECRET_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/bon5ai-remote/proxy-secret}"
HEADER="${HEADER:-X-Origin-Verify}"

if [ -n "$DOMAIN" ] && [ -z "$CERT" ]; then
    echo "deploy.sh: a custom domain needs an ACM certificate ARN in us-east-1" >&2
    exit 2
fi

umask 077
if [ ! -s "$SECRET_FILE" ]; then
    mkdir -p "$(dirname "$SECRET_FILE")"
    python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > "$SECRET_FILE"
    echo "Generated a new origin secret in $SECRET_FILE"
fi

PARAMS="$(mktemp)"
trap 'rm -f "$PARAMS"' EXIT
python3 - "$SECRET_FILE" "$ORIGIN" "$PORT" "$HEADER" "$DOMAIN" "$CERT" > "$PARAMS" <<'PY'
import json, sys
secret_file, origin, port, header, domain, cert = sys.argv[1:]
values = {"OriginDomainName": origin, "OriginHttpsPort": port, "OriginSecretHeaderName": header,
          "OriginSecret": open(secret_file).read().strip(), "AlternateDomainName": domain,
          "AcmCertificateArn": cert}
print(json.dumps([{"ParameterKey": key, "ParameterValue": value} for key, value in values.items()]))
PY

aws cloudformation deploy --stack-name "$STACK" --template-file "$HERE/cloudfront.yaml" \
    --parameter-overrides "file://$PARAMS" --no-fail-on-empty-changeset

aws cloudformation describe-stacks --stack-name "$STACK" \
    --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output text

cat <<EOF

Next, in ~/.config/bon5ai-remote/config.toml:

  proxy_secret_file = "$SECRET_FILE"

  [[listener]]
  address = "127.0.0.1:8095"
  public_url = "<PublicUrl above>"
  proxy_header = "$HEADER"
  allowed_hosts = ["$ORIGIN", "$ORIGIN:$PORT"]

Then restart the gate (systemctl --user restart bon5ai-remote) and run: bon5ai-remote doctor
EOF
