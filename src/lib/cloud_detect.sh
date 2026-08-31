# cloud_detect.sh -- work out which clouds can be scanned, and gather each one's
# authorization export with read only calls. Every gather call is enumeration only:
# it lists and reads configuration, it never creates, changes, or deletes anything,
# and it never reads the contents of a secret, object, or key.

# which clouds are reachable in this shell (CLI present and signed in)
detect_clouds() {
  local found=()
  if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; then found+=("aws"); fi
  if command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; then found+=("azure"); fi
  if command -v gcloud >/dev/null 2>&1 && [ -n "$(gcloud config get-value project 2>/dev/null)" ]; then found+=("gcp"); fi
  if command -v kubectl >/dev/null 2>&1 && kubectl config current-context >/dev/null 2>&1; then found+=("k8s"); fi
  printf '%s\n' "${found[@]}"
}

# peek at a saved export and say which cloud it is from
detect_from_file() {
  local f="$1"
  if jq -e '(.UserDetailList // .RoleDetailList // .Policies) != null' "$f" >/dev/null 2>&1; then echo aws
  elif jq -e '(.roleAssignments // .roleDefinitions) != null' "$f" >/dev/null 2>&1; then echo azure
  elif jq -e '.bindings != null' "$f" >/dev/null 2>&1; then echo gcp
  elif jq -e '[.items[]?.kind] | any(. == "ClusterRole" or . == "Role" or . == "ClusterRoleBinding" or . == "RoleBinding")' "$f" >/dev/null 2>&1; then echo k8s
  else echo ""; fi
}

gather_aws() {
  log_step "reading AWS IAM (get-account-authorization-details, read only)"
  run_readonly aws aws iam get-account-authorization-details --output json > "$WORKDIR/aws.json"
}

gather_azure() {
  log_step "reading Azure RBAC (role assignment list and role definition list, read only)"
  run_readonly az az role assignment list --all -o json > "$WORKDIR/az_assign.json"
  run_readonly az az role definition list -o json > "$WORKDIR/az_defs.json"
  jq -n --slurpfile a "$WORKDIR/az_assign.json" --slurpfile d "$WORKDIR/az_defs.json" \
     '{roleAssignments: ($a[0] // []), roleDefinitions: ($d[0] // [])}' > "$WORKDIR/azure.json"
}

gather_gcp() {
  local proj; proj="$(gcloud config get-value project 2>/dev/null)"
  log_step "reading GCP IAM policy for project $proj (get-iam-policy, read only)"
  run_readonly gcloud gcloud projects get-iam-policy "$proj" --format=json > "$WORKDIR/gcp.json"
}

gather_k8s() {
  log_step "reading Kubernetes RBAC (get clusterroles, roles, and their bindings, read only)"
  run_readonly kubectl kubectl get clusterroles,clusterrolebindings,roles,rolebindings -A -o json > "$WORKDIR/k8s.json"
}

gather_aws_credentials() {
  log_step "reading the AWS credential report (generate and get, read only report)"
  run_readonly aws aws iam generate-credential-report >/dev/null 2>&1 || true
  # the report can take a moment to become ready; poll a few times
  local i out
  for i in 1 2 3 4 5; do
    out="$(run_readonly aws aws iam get-credential-report --query Content --output text 2>/dev/null)"
    if [ -n "$out" ]; then
      printf '%s' "$out" | base64 --decode > "$WORKDIR/aws-credentials.csv" 2>/dev/null && return 0
    fi
    sleep 2
  done
  log_warn "could not read the credential report"
  return 1
}

gather_aws_exposure() {
  log_step "reading S3 and KMS resource policies (list and get policy, read only)"
  local acct; acct="$(run_readonly aws aws sts get-caller-identity --query Account --output text 2>/dev/null)"
  local blist="$WORKDIR/_bnames.txt" klist="$WORKDIR/_knames.txt"
  local tmpb="$WORKDIR/_buckets.jsonl" tmpk="$WORKDIR/_keys.jsonl"
  : > "$tmpb"; : > "$tmpk"
  run_readonly aws aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' > "$blist"
  local name pol pab
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    pol="$(run_readonly aws aws s3api get-bucket-policy --bucket "$name" --query Policy --output text 2>/dev/null)"
    pab="$(run_readonly aws aws s3api get-public-access-block --bucket "$name" --query PublicAccessBlockConfiguration --output json 2>/dev/null)"
    [ -n "$pab" ] || pab="null"
    jq -nc --arg name "$name" --arg pol "$pol" --argjson pab "$pab" \
      '{name:$name, policy:(if $pol=="" then null else ($pol|fromjson) end), publicAccessBlock:$pab}' >> "$tmpb" 2>/dev/null
  done < "$blist"
  run_readonly aws aws kms list-keys --query 'Keys[].KeyId' --output text 2>/dev/null | tr '\t' '\n' > "$klist"
  local kid kpol
  while IFS= read -r kid; do
    [ -n "$kid" ] || continue
    kpol="$(run_readonly aws aws kms get-key-policy --key-id "$kid" --policy-name default --query Policy --output text 2>/dev/null)"
    jq -nc --arg kid "$kid" --arg kpol "$kpol" \
      '{keyId:$kid, policy:(if $kpol=="" then null else ($kpol|fromjson) end)}' >> "$tmpk" 2>/dev/null
  done < "$klist"
  jq -nc --arg acct "$acct" --slurpfile b "$tmpb" --slurpfile k "$tmpk" \
    '{account:$acct, buckets:$b, kmsKeys:$k}' > "$WORKDIR/aws-resource-policies.json"
}

export_path_for() { echo "$WORKDIR/$1.json"; }
