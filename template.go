package main

const tpl = `#### DIEC

{{- if .Results.Filetype}}
**File type:** ` + "`" + `{{ .Results.Filetype }}` + "`" + `
{{- end }}
**Packed:** {{ if .Results.Packed }}Yes{{ else }}No{{ end }}
{{- if .Results.Status}}
**Status:** {{ .Results.Status }}
{{- end }}
{{- if .Results.Packagers}}

##### Packers / Protectors
{{range .Results.Packagers}}
  - ` + "`" + `{{ . -}}` + "`" + `
{{- end }}
{{- end }}
{{- if .Results.Values}}

##### Values
{{range .Results.Values}}
  - **{{ .Name }}** ({{ .Type }}){{ if .Version }}: {{ .Version }}{{ end }}
{{- end }}
{{- end }}
{{- if .Results.Info}}

##### Info
{{range $k, $v := .Results.Info}}
  - {{ $k }}: {{ $v }}
{{- end }}
{{- end }}
{{- if .Results.Entropy}}

##### Entropy
  - Max: {{ .Results.Entropy.Max }}
  - Packed: {{ if .Results.Entropy.Packed }}Yes{{ else }}No{{ end }}
{{- end }}
`
