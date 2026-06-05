package httpserver

import "embed"

//go:embed static/*
var embeddedStatic embed.FS
