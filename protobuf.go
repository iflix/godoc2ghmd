package main

import (
	"fmt"
	"strings"
)

func fmtProtobufDoc(doc string) string {
	prelude := ""
	didProtoFiles := false
	protoFiles := ""
	hasProtoTLMPrelude := false
	didProtoTLM := false
	protoTLM := ""
	other := ""

	lines := strings.Split(doc, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !didProtoFiles && strings.Contains(line, *protobufPreludeMatcher) {
			trimmed := strings.Replace(trimmed, "protocol buffer", "[Protobuf](https://developers.google.com/protocol-buffers/)-compatible", 1)
			protoFiles += "**" + trimmed + "**\n\n"
			continue
		}

		if !didProtoFiles && protoFiles != "" {
			if trimmed == "" {
				continue
			}
			if strings.Contains(trimmed, *protobufFilesMatcher) {
				protoFiles += trimmed + "\n\n"
				continue
			}
			if !strings.Contains(trimmed, *protobufMessagesMatcher) {
				protoFiles += fmt.Sprintf("- [%s](./%s)\n", trimmed, trimmed)
				continue
			}
			hasProtoTLMPrelude = true
			didProtoFiles = true
			continue
		}

		if !didProtoTLM && hasProtoTLMPrelude {
			if trimmed == "" {
				didProtoTLM = true
				continue
			}
			protoTLM += fmt.Sprintf("- [%s](#%s)\n", trimmed, trimmed)
			continue
		}

		if !didProtoFiles && !didProtoTLM {
			prelude += line + "\n"
		} else {
			other += line + "\n"
		}
	}

	if protoTLM != "" {
		protoTLM = "It has these top-level [Protobuf](https://developers.google.com/protocol-buffers/)-compatible message types:\n\n" + protoTLM + "\n"
	}

	return strings.TrimSpace(prelude + "\n" + other + "\n" + protoFiles + "\n" + protoTLM)
}
