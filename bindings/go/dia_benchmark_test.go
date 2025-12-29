package dia

import (
	"testing"
)

// Helper for benchmarks - creates test configs using the shared test server config
func benchCreateConfig(b *testing.B, phone, name string) *Config {
	b.Helper()

	keys, request, err := CreateEnrollmentRequest(phone, name, "https://example.com/logo.png", 1)
	if err != nil {
		b.Fatalf("CreateEnrollmentRequest: %v", err)
	}
	defer keys.Close()

	response, err := testServerConfig.ProcessEnrollment(request)
	if err != nil {
		b.Fatalf("ProcessEnrollment: %v", err)
	}

	cfg, err := FinalizeEnrollment(keys, response, phone, name, "https://example.com/logo.png")
	if err != nil {
		b.Fatalf("FinalizeEnrollment: %v", err)
	}

	return cfg
}

// ============================================================================
// Enrollment Benchmarks
// ============================================================================

func BenchmarkEnrollment_CreateRequest(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		keys, _, err := CreateEnrollmentRequest("+1555123456", "Benchmark User", "https://example.com/logo.png", 1)
		if err != nil {
			b.Fatalf("CreateEnrollmentRequest: %v", err)
		}
		keys.Close()
	}
}

func BenchmarkEnrollment_FullFlow(b *testing.B) {
	b.ReportAllocs()

	// Setup server config once
	ciPrivate := make([]byte, 32)
	ciPublic := make([]byte, 96)
	atPrivate := make([]byte, 32)
	atPublic := make([]byte, 96)
	amfPrivate := make([]byte, 32)
	amfPublic := make([]byte, 48)
	for i := range ciPrivate {
		ciPrivate[i] = byte(i + 1)
	}
	for i := range ciPublic {
		ciPublic[i] = byte(i + 10)
	}
	for i := range atPrivate {
		atPrivate[i] = byte(i + 20)
	}
	for i := range atPublic {
		atPublic[i] = byte(i + 30)
	}
	for i := range amfPrivate {
		amfPrivate[i] = byte(i + 35)
	}
	for i := range amfPublic {
		amfPublic[i] = byte(i + 40)
	}

	serverCfg, err := NewServerConfig(ciPrivate, ciPublic, atPrivate, atPublic, amfPrivate, amfPublic, 30)
	if err != nil {
		b.Fatalf("NewServerConfig: %v", err)
	}
	defer serverCfg.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keys, request, err := CreateEnrollmentRequest("+1555123456", "Benchmark User", "https://example.com/logo.png", 1)
		if err != nil {
			b.Fatalf("CreateEnrollmentRequest: %v", err)
		}

		response, err := serverCfg.ProcessEnrollment(request)
		if err != nil {
			b.Fatalf("ProcessEnrollment: %v", err)
		}

		cfg, err := FinalizeEnrollment(keys, response, "+1555123456", "Benchmark User", "https://example.com/logo.png")
		if err != nil {
			b.Fatalf("FinalizeEnrollment: %v", err)
		}

		keys.Close()
		cfg.Close()
	}
}

// ============================================================================
// Config Benchmarks
// ============================================================================

func BenchmarkConfig_ToEnv(b *testing.B) {
	cfg := benchCreateConfig(b, "+1555123456", "Benchmark")
	defer cfg.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cfg.ToEnv()
		if err != nil {
			b.Fatalf("ToEnv: %v", err)
		}
	}
}

func BenchmarkConfig_FromEnv(b *testing.B) {
	cfg := benchCreateConfig(b, "+1555123456", "Benchmark")
	envStr, err := cfg.ToEnv()
	if err != nil {
		b.Fatalf("ToEnv: %v", err)
	}
	cfg.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := ConfigFromEnv(envStr)
		if err != nil {
			b.Fatalf("ConfigFromEnv: %v", err)
		}
		parsed.Close()
	}
}

// ============================================================================
// CallState Benchmarks
// ============================================================================

func BenchmarkCallState_Create(b *testing.B) {
	cfg := benchCreateConfig(b, "+1555123456", "Benchmark")
	defer cfg.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs, err := NewCallState(cfg, "+1555987654", true)
		if err != nil {
			b.Fatalf("NewCallState: %v", err)
		}
		cs.Close()
	}
}

// ============================================================================
// AKE Benchmarks
// ============================================================================

func BenchmarkAKE_Init(b *testing.B) {
	cfg := benchCreateConfig(b, "+1555123456", "Benchmark")
	defer cfg.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs, _ := NewCallState(cfg, "+1555987654", true)
		if err := cs.AKEInit(); err != nil {
			b.Fatalf("AKEInit: %v", err)
		}
		cs.Close()
	}
}

func BenchmarkAKE_Request(b *testing.B) {
	cfg := benchCreateConfig(b, "+1555123456", "Benchmark")
	defer cfg.Close()

	cs, _ := NewCallState(cfg, "+1555987654", true)
	defer cs.Close()
	cs.AKEInit()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cs.AKERequest()
		if err != nil {
			b.Fatalf("AKERequest: %v", err)
		}
	}
}

func BenchmarkAKE_FullExchange(b *testing.B) {
	callerCfg := benchCreateConfig(b, "+1111111111", "Alice")
	defer callerCfg.Close()
	recipientCfg := benchCreateConfig(b, "+2222222222", "Bob")
	defer recipientCfg.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callerState, _ := NewCallState(callerCfg, "+2222222222", true)
		recipientState, _ := NewCallState(recipientCfg, "+1111111111", false)

		callerState.AKEInit()
		recipientState.AKEInit()

		request, _ := callerState.AKERequest()
		response, _ := recipientState.AKEResponse(request)
		complete, _ := callerState.AKEComplete(response)
		recipientState.AKEFinalize(complete)

		callerState.Close()
		recipientState.Close()
	}
}

// ============================================================================
// RUA Benchmarks
// ============================================================================

func BenchmarkRUA_FullExchange(b *testing.B) {
	callerCfg := benchCreateConfig(b, "+1111111111", "Alice")
	defer callerCfg.Close()
	recipientCfg := benchCreateConfig(b, "+2222222222", "Bob")
	defer recipientCfg.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callerState, _ := NewCallState(callerCfg, "+2222222222", true)
		recipientState, _ := NewCallState(recipientCfg, "+1111111111", false)

		// AKE
		callerState.AKEInit()
		recipientState.AKEInit()
		request, _ := callerState.AKERequest()
		response, _ := recipientState.AKEResponse(request)
		complete, _ := callerState.AKEComplete(response)
		recipientState.AKEFinalize(complete)

		// RUA
		callerState.TransitionToRUA()
		recipientState.TransitionToRUA()
		callerState.RUAInit()
		recipientState.RUAInit()
		ruaReq, _ := callerState.RUARequest()
		ruaResp, _ := recipientState.RUAResponse(ruaReq)
		callerState.RUAFinalize(ruaResp)

		callerState.Close()
		recipientState.Close()
	}
}

// ============================================================================
// DR Messaging Benchmarks
// ============================================================================

func BenchmarkDR_Encrypt(b *testing.B) {
	callerCfg := benchCreateConfig(b, "+1111111111", "Alice")
	defer callerCfg.Close()
	recipientCfg := benchCreateConfig(b, "+2222222222", "Bob")
	defer recipientCfg.Close()

	callerState, _ := NewCallState(callerCfg, "+2222222222", true)
	defer callerState.Close()
	recipientState, _ := NewCallState(recipientCfg, "+1111111111", false)
	defer recipientState.Close()

	// Complete AKE + RUA setup
	callerState.AKEInit()
	recipientState.AKEInit()
	request, _ := callerState.AKERequest()
	response, _ := recipientState.AKEResponse(request)
	complete, _ := callerState.AKEComplete(response)
	recipientState.AKEFinalize(complete)

	callerState.TransitionToRUA()
	recipientState.TransitionToRUA()
	callerState.RUAInit()
	recipientState.RUAInit()
	ruaReq, _ := callerState.RUARequest()
	ruaResp, _ := recipientState.RUAResponse(ruaReq)
	callerState.RUAFinalize(ruaResp)

	plaintext := []byte("Hello, this is a benchmark message for encryption!")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := callerState.Encrypt(plaintext)
		if err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
	}
}

func BenchmarkDR_EncryptDecrypt(b *testing.B) {
	callerCfg := benchCreateConfig(b, "+1111111111", "Alice")
	defer callerCfg.Close()
	recipientCfg := benchCreateConfig(b, "+2222222222", "Bob")
	defer recipientCfg.Close()

	callerState, _ := NewCallState(callerCfg, "+2222222222", true)
	defer callerState.Close()
	recipientState, _ := NewCallState(recipientCfg, "+1111111111", false)
	defer recipientState.Close()

	// Complete AKE + RUA setup
	callerState.AKEInit()
	recipientState.AKEInit()
	request, _ := callerState.AKERequest()
	response, _ := recipientState.AKEResponse(request)
	complete, _ := callerState.AKEComplete(response)
	recipientState.AKEFinalize(complete)

	callerState.TransitionToRUA()
	recipientState.TransitionToRUA()
	callerState.RUAInit()
	recipientState.RUAInit()
	ruaReq, _ := callerState.RUARequest()
	ruaResp, _ := recipientState.RUAResponse(ruaReq)
	callerState.RUAFinalize(ruaResp)

	plaintext := []byte("Hello, this is a benchmark message for round-trip!")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, err := callerState.Encrypt(plaintext)
		if err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
		_, err = recipientState.Decrypt(ciphertext)
		if err != nil {
			b.Fatalf("Decrypt: %v", err)
		}
	}
}

// ============================================================================
// Message Benchmarks
// ============================================================================

func BenchmarkMessage_Parse(b *testing.B) {
	cfg := benchCreateConfig(b, "+1111111111", "Benchmark")
	defer cfg.Close()

	cs, _ := NewCallState(cfg, "+2222222222", true)
	defer cs.Close()
	cs.AKEInit()

	request, _ := cs.AKERequest()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg, err := ParseMessage(request)
		if err != nil {
			b.Fatalf("ParseMessage: %v", err)
		}
		msg.Close()
	}
}

func BenchmarkMessage_CreateBye(b *testing.B) {
	cfg := benchCreateConfig(b, "+1111111111", "Benchmark")
	defer cfg.Close()

	cs, _ := NewCallState(cfg, "+2222222222", true)
	defer cs.Close()
	cs.AKEInit()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cs.CreateByeMessage()
		if err != nil {
			b.Fatalf("CreateByeMessage: %v", err)
		}
	}
}

func BenchmarkMessage_CreateHeartbeat(b *testing.B) {
	cfg := benchCreateConfig(b, "+1111111111", "Benchmark")
	defer cfg.Close()

	cs, _ := NewCallState(cfg, "+2222222222", true)
	defer cs.Close()
	cs.AKEInit()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cs.CreateHeartbeatMessage()
		if err != nil {
			b.Fatalf("CreateHeartbeatMessage: %v", err)
		}
	}
}

// ============================================================================
// Full Protocol Benchmarks
// ============================================================================

func BenchmarkProtocol_FullCallSetup(b *testing.B) {
	// Benchmark complete call setup: enrollment + AKE + RUA
	b.ReportAllocs()

	// Setup server once
	ciPrivate := make([]byte, 32)
	ciPublic := make([]byte, 96)
	atPrivate := make([]byte, 32)
	atPublic := make([]byte, 96)
	amfPrivate := make([]byte, 32)
	amfPublic := make([]byte, 48)
	for i := range ciPrivate {
		ciPrivate[i] = byte(i + 1)
	}
	for i := range ciPublic {
		ciPublic[i] = byte(i + 10)
	}
	for i := range atPrivate {
		atPrivate[i] = byte(i + 20)
	}
	for i := range atPublic {
		atPublic[i] = byte(i + 30)
	}
	for i := range amfPrivate {
		amfPrivate[i] = byte(i + 35)
	}
	for i := range amfPublic {
		amfPublic[i] = byte(i + 40)
	}

	serverCfg, _ := NewServerConfig(ciPrivate, ciPublic, atPrivate, atPublic, amfPrivate, amfPublic, 30)
	defer serverCfg.Close()

	// Pre-enroll both parties
	keys1, req1, _ := CreateEnrollmentRequest("+1111111111", "Alice", "https://example.com/alice.png", 1)
	resp1, _ := serverCfg.ProcessEnrollment(req1)
	callerCfg, _ := FinalizeEnrollment(keys1, resp1, "+1111111111", "Alice", "https://example.com/alice.png")
	keys1.Close()
	defer callerCfg.Close()

	keys2, req2, _ := CreateEnrollmentRequest("+2222222222", "Bob", "https://example.com/bob.png", 1)
	resp2, _ := serverCfg.ProcessEnrollment(req2)
	recipientCfg, _ := FinalizeEnrollment(keys2, resp2, "+2222222222", "Bob", "https://example.com/bob.png")
	keys2.Close()
	defer recipientCfg.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callerState, _ := NewCallState(callerCfg, "+2222222222", true)
		recipientState, _ := NewCallState(recipientCfg, "+1111111111", false)

		// AKE
		callerState.AKEInit()
		recipientState.AKEInit()
		request, _ := callerState.AKERequest()
		response, _ := recipientState.AKEResponse(request)
		complete, _ := callerState.AKEComplete(response)
		recipientState.AKEFinalize(complete)

		// RUA
		callerState.TransitionToRUA()
		recipientState.TransitionToRUA()
		callerState.RUAInit()
		recipientState.RUAInit()
		ruaReq, _ := callerState.RUARequest()
		ruaResp, _ := recipientState.RUAResponse(ruaReq)
		callerState.RUAFinalize(ruaResp)

		callerState.Close()
		recipientState.Close()
	}
}
