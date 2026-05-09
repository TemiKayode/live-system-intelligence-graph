{{/*
Expand the name of the chart.
*/}}
{{- define "lsig.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lsig.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "lsig.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lsig.labels" -}}
helm.sh/chart: {{ include "lsig.chart" . }}
{{ include "lsig.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "lsig.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lsig.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
