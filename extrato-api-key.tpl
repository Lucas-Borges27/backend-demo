{{- with secret "kvapigee-demo/data/extrato-api-key" -}}
{{ .Data.data.api_key }}
{{- end }}
