# credentials_aws: read the AWS credential report and flag root keys, console users
# without a second factor, doubled up keys, and old keys that are still active. The
# report describes the account, it is not a policy; reading it changes no principal.

analyze_credentials_aws() {
  local csv="$1" maxage="${2:-90}"
  jq -R -s --argjson maxage "$maxage" '
    def dsince($d):
      if ($d | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")) then
        ((now - (($d[0:19]) | strptime("%Y-%m-%dT%H:%M:%S") | mktime)) / 86400 | floor)
      else -1 end;
    def cfind($id;$sev;$title;$name;$kind;$detail;$fix):
      {id:$id, severity:$sev, title:$title, principal:{kind:$kind, name:$name, arn:$name},
       detail:$detail, fix:$fix, tactic:"credential exposure"};
    (gsub("\r";"") | split("\n") | map(select(length>0))) as $lines
    | ($lines[0] | split(",")) as $h
    | ($lines[1:] | map(split(",") | . as $r | reduce range(0;($h|length)) as $i ({}; .[$h[$i]] = ($r[$i] // "")))) as $rows
    | [ $rows[] as $u | ($u.user) as $name
        | if ($name == "<root_account>") then
            ( if ($u.access_key_1_active == "true" or $u.access_key_2_active == "true") then
                cfind("c-rootkey";"critical";"Root account has an active access key";$name;"account";
                  "The root account still has an active access key. Root keys cannot be scoped and are a first target once an account is breached.";
                  "Delete the root access keys and operate through least privilege roles instead.") else empty end ),
            ( if ($u.mfa_active == "false") then
                cfind("c-rootmfa";"critical";"Root account has no multi factor authentication";$name;"account";
                  "The root account can sign in to the console with no second factor.";
                  "Enable a hardware or virtual multi factor device on the root account.") else empty end )
          else
            ( if ($u.password_enabled == "true" and $u.mfa_active == "false") then
                cfind("c-mfa";"high";"Console user without multi factor authentication";$name;"user";
                  ($name + " can sign in to the console with a password and no second factor, so a phished or reused password is enough to sign in.");
                  "Require a multi factor device for every user with console access.") else empty end ),
            ( if ($u.access_key_1_active == "true" and $u.access_key_2_active == "true") then
                cfind("c-twokeys";"medium";"User has two active access keys";$name;"user";
                  ($name + " has two active access keys. A second key doubles the chance one leaks and is often a forgotten credential.");
                  "Keep one active key per user, and delete the other after rotating.") else empty end ),
            ( [ {a:$u.access_key_1_active, r:$u.access_key_1_last_rotated},
                {a:$u.access_key_2_active, r:$u.access_key_2_last_rotated} ][]
              | select(.a == "true" and (dsince(.r) > $maxage))
              | cfind("c-oldkey";"medium";"Access key is old and still active";$name;"user";
                  ($name + " has an access key last rotated " + ((dsince(.r))|tostring) + " days ago and still active. A leaked long lived key stays valid until it is rotated.");
                  "Rotate keys on a schedule, and delete keys that are unused.") )
          end
      ]' "$csv"
}
