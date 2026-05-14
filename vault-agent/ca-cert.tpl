{{- with secret "pki/issuer/apigee-ca" -}}
{{ .Data.certificate }}
{{- end }}
