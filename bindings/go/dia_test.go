package dia

import (
	"bytes"
	"strings"
	"testing"
)

// Shared server config for all tests (avoids key generation overhead)
var testServerConfig *ServerConfig

func init() {
	var err error
	testServerConfig, err = GenerateServerConfig(30)
	if err != nil {
		panic("failed to generate test server config: " + err.Error())
	}
}

// Helper to create a test configuration using enrollment
func createTestConfig(t *testing.T, phone, name string) *Config {
	t.Helper()

	// Client creates enrollment request
	keys, request, err := CreateEnrollmentRequest(phone, name, "https://example.com/logo.png", 1)
	if err != nil {
		t.Fatalf("CreateEnrollmentRequest: %v", err)
	}
	defer keys.Close()

	// Server processes request
	response, err := testServerConfig.ProcessEnrollment(request)
	if err != nil {
		t.Fatalf("ProcessEnrollment: %v", err)
	}

	// Client finalizes enrollment
	cfg, err := FinalizeEnrollment(keys, response, phone, name, "https://example.com/logo.png")
	if err != nil {
		t.Fatalf("FinalizeEnrollment: %v", err)
	}

	return cfg
}

// ============================================================================
// Config Tests
// ============================================================================

func TestConfig_EnrollmentFlow(t *testing.T) {
	cfg := createTestConfig(t, "+1234567890", "Test User")
	defer cfg.Close()

	// Verify config can be serialized
	envStr, err := cfg.ToEnv()
	if err != nil {
		t.Fatalf("ToEnv: %v", err)
	}

	if !strings.Contains(envStr, "+1234567890") {
		t.Error("Config should contain phone number")
	}
	if !strings.Contains(envStr, "Test User") {
		t.Error("Config should contain name")
	}
}

func TestConfig_RoundTrip(t *testing.T) {
	cfg1 := createTestConfig(t, "+1555123456", "Alice")
	defer cfg1.Close()

	// Serialize
	envStr, err := cfg1.ToEnv()
	if err != nil {
		t.Fatalf("ToEnv: %v", err)
	}

	// Parse back
	cfg2, err := ConfigFromEnv(envStr)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	defer cfg2.Close()

	// Serialize again and compare
	envStr2, err := cfg2.ToEnv()
	if err != nil {
		t.Fatalf("ToEnv (round 2): %v", err)
	}

	if envStr != envStr2 {
		t.Error("Config round-trip failed")
	}
}

// ============================================================================
// CallState Tests
// ============================================================================

func TestCallState_Creation(t *testing.T) {
	cfg := createTestConfig(t, "+1111111111", "Caller")
	defer cfg.Close()

	cs, err := NewCallState(cfg, "+2222222222", true)
	if err != nil {
		t.Fatalf("NewCallState: %v", err)
	}
	defer cs.Close()

	if !cs.IsCaller() {
		t.Error("Should be caller")
	}
	if cs.IsRecipient() {
		t.Error("Should not be recipient")
	}

	// AKE topic requires AKEInit to be called first
	if err := cs.AKEInit(); err != nil {
		t.Fatalf("AKEInit: %v", err)
	}

	topic, err := cs.AKETopic()
	if err != nil {
		t.Fatalf("AKETopic: %v", err)
	}
	if topic == "" {
		t.Error("AKE topic should not be empty")
	}
}

func TestCallState_RecipientRole(t *testing.T) {
	cfg := createTestConfig(t, "+3333333333", "Recipient")
	defer cfg.Close()

	cs, err := NewCallState(cfg, "+4444444444", false)
	if err != nil {
		t.Fatalf("NewCallState: %v", err)
	}
	defer cs.Close()

	if cs.IsCaller() {
		t.Error("Should not be caller")
	}
	if !cs.IsRecipient() {
		t.Error("Should be recipient")
	}
}

// ============================================================================
// AKE Protocol Tests
// ============================================================================

func TestAKE_FullExchange(t *testing.T) {
	// Setup caller and recipient configs
	callerCfg := createTestConfig(t, "+1111111111", "Alice")
	defer callerCfg.Close()
	recipientCfg := createTestConfig(t, "+2222222222", "Bob")
	defer recipientCfg.Close()

	// Create call states
	callerState, err := NewCallState(callerCfg, "+2222222222", true)
	if err != nil {
		t.Fatalf("NewCallState (caller): %v", err)
	}
	defer callerState.Close()

	recipientState, err := NewCallState(recipientCfg, "+1111111111", false)
	if err != nil {
		t.Fatalf("NewCallState (recipient): %v", err)
	}
	defer recipientState.Close()

	// Initialize AKE
	if err := callerState.AKEInit(); err != nil {
		t.Fatalf("AKEInit (caller): %v", err)
	}
	if err := recipientState.AKEInit(); err != nil {
		t.Fatalf("AKEInit (recipient): %v", err)
	}

	// Verify both parties derive the same AKE topic
	callerTopic, err := callerState.AKETopic()
	if err != nil {
		t.Fatalf("AKETopic (caller): %v", err)
	}
	recipientTopic, err := recipientState.AKETopic()
	if err != nil {
		t.Fatalf("AKETopic (recipient): %v", err)
	}
	if callerTopic != recipientTopic {
		t.Errorf("AKE topics don't match: caller=%s, recipient=%s", callerTopic, recipientTopic)
	}
	if len(callerTopic) == 0 {
		t.Error("AKE topic should not be empty")
	}

	// 1. Caller creates request
	request, err := callerState.AKERequest()
	if err != nil {
		t.Fatalf("AKERequest: %v", err)
	}

	// 2. Recipient processes request and creates response
	response, err := recipientState.AKEResponse(request)
	if err != nil {
		t.Fatalf("AKEResponse: %v", err)
	}

	// 3. Caller processes response and creates complete
	complete, err := callerState.AKEComplete(response)
	if err != nil {
		t.Fatalf("AKEComplete: %v", err)
	}

	// 4. Recipient finalizes
	if err := recipientState.AKEFinalize(complete); err != nil {
		t.Fatalf("AKEFinalize: %v", err)
	}

	// Verify shared keys match
	callerKey, err := callerState.SharedKey()
	if err != nil {
		t.Fatalf("SharedKey (caller): %v", err)
	}
	recipientKey, err := recipientState.SharedKey()
	if err != nil {
		t.Fatalf("SharedKey (recipient): %v", err)
	}

	if !bytes.Equal(callerKey, recipientKey) {
		t.Errorf("Shared keys do not match: caller len=%d, recipient len=%d", len(callerKey), len(recipientKey))
	}
	if len(callerKey) == 0 {
		t.Error("Shared key should not be empty")
	}
	if len(callerKey) != 32 {
		t.Errorf("Shared key length = %d, want 32", len(callerKey))
	}

	// Verify tickets are present
	callerTicket, err := callerState.Ticket()
	if err != nil {
		t.Fatalf("Ticket (caller): %v", err)
	}
	if len(callerTicket) == 0 {
		t.Error("Caller ticket should not be empty")
	}

	recipientTicket, err := recipientState.Ticket()
	if err != nil {
		t.Fatalf("Ticket (recipient): %v", err)
	}
	if len(recipientTicket) == 0 {
		t.Error("Recipient ticket should not be empty")
	}

	// Verify sender IDs are set
	callerSenderID, err := callerState.SenderID()
	if err != nil {
		t.Fatalf("SenderID (caller): %v", err)
	}
	if callerSenderID == "" {
		t.Error("Caller sender ID should not be empty")
	}

	recipientSenderID, err := recipientState.SenderID()
	if err != nil {
		t.Fatalf("SenderID (recipient): %v", err)
	}
	if recipientSenderID == "" {
		t.Error("Recipient sender ID should not be empty")
	}
}

// ============================================================================
// RUA Protocol Tests
// ============================================================================

func TestRUA_AfterAKE(t *testing.T) {
	// Setup with full AKE exchange first
	callerCfg := createTestConfig(t, "+1111111111", "Alice")
	defer callerCfg.Close()
	recipientCfg := createTestConfig(t, "+2222222222", "Bob")
	defer recipientCfg.Close()

	callerState, _ := NewCallState(callerCfg, "+2222222222", true)
	defer callerState.Close()
	recipientState, _ := NewCallState(recipientCfg, "+1111111111", false)
	defer recipientState.Close()

	// Complete AKE
	callerState.AKEInit()
	recipientState.AKEInit()
	request, _ := callerState.AKERequest()
	response, _ := recipientState.AKEResponse(request)
	complete, _ := callerState.AKEComplete(response)
	recipientState.AKEFinalize(complete)

	// Transition to RUA
	if err := callerState.TransitionToRUA(); err != nil {
		t.Fatalf("TransitionToRUA (caller): %v", err)
	}
	if err := recipientState.TransitionToRUA(); err != nil {
		t.Fatalf("TransitionToRUA (recipient): %v", err)
	}

	// Initialize RUA
	if err := callerState.RUAInit(); err != nil {
		t.Fatalf("RUAInit (caller): %v", err)
	}
	if err := recipientState.RUAInit(); err != nil {
		t.Fatalf("RUAInit (recipient): %v", err)
	}

	// RUA exchange
	ruaRequest, err := callerState.RUARequest()
	if err != nil {
		t.Fatalf("RUARequest: %v", err)
	}

	ruaResponse, err := recipientState.RUAResponse(ruaRequest)
	if err != nil {
		t.Fatalf("RUAResponse: %v", err)
	}

	if err := callerState.RUAFinalize(ruaResponse); err != nil {
		t.Fatalf("RUAFinalize: %v", err)
	}

	// Verify remote party info
	callerRemote, err := callerState.RemoteParty()
	if err != nil {
		t.Fatalf("RemoteParty (caller): %v", err)
	}
	if !callerRemote.Verified {
		t.Error("Remote party should be verified after RUA")
	}
	if callerRemote.Phone != "+2222222222" {
		t.Errorf("Caller's remote phone = %q, want %q", callerRemote.Phone, "+2222222222")
	}
	if callerRemote.Name != "Bob" {
		t.Errorf("Caller's remote name = %q, want %q", callerRemote.Name, "Bob")
	}

	recipientRemote, err := recipientState.RemoteParty()
	if err != nil {
		t.Fatalf("RemoteParty (recipient): %v", err)
	}
	if !recipientRemote.Verified {
		t.Error("Recipient's remote party should be verified after RUA")
	}
	if recipientRemote.Phone != "+1111111111" {
		t.Errorf("Recipient's remote phone = %q, want %q", recipientRemote.Phone, "+1111111111")
	}
	if recipientRemote.Name != "Alice" {
		t.Errorf("Recipient's remote name = %q, want %q", recipientRemote.Name, "Alice")
	}
}

// ============================================================================
// DR Messaging Tests
// ============================================================================

func TestDR_EncryptDecrypt(t *testing.T) {
	// Full setup: AKE + RUA
	callerCfg := createTestConfig(t, "+1111111111", "Alice")
	defer callerCfg.Close()
	recipientCfg := createTestConfig(t, "+2222222222", "Bob")
	defer recipientCfg.Close()

	callerState, _ := NewCallState(callerCfg, "+2222222222", true)
	defer callerState.Close()
	recipientState, _ := NewCallState(recipientCfg, "+1111111111", false)
	defer recipientState.Close()

	// Complete AKE
	callerState.AKEInit()
	recipientState.AKEInit()
	request, _ := callerState.AKERequest()
	response, _ := recipientState.AKEResponse(request)
	complete, _ := callerState.AKEComplete(response)
	recipientState.AKEFinalize(complete)

	// Complete RUA
	callerState.TransitionToRUA()
	recipientState.TransitionToRUA()
	callerState.RUAInit()
	recipientState.RUAInit()
	ruaReq, _ := callerState.RUARequest()
	ruaResp, _ := recipientState.RUAResponse(ruaReq)
	callerState.RUAFinalize(ruaResp)

	// Test encryption/decryption (caller -> recipient)
	plaintext1 := []byte("Hello, secure world!")

	ciphertext1, err := callerState.Encrypt(plaintext1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted1, err := recipientState.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext1, decrypted1) {
		t.Errorf("Decrypted message mismatch: got %q, want %q", decrypted1, plaintext1)
	}

	// Test bidirectional (recipient -> caller)
	plaintext2 := []byte("Response from recipient")

	ciphertext2, err := recipientState.Encrypt(plaintext2)
	if err != nil {
		t.Fatalf("Encrypt (recipient): %v", err)
	}

	decrypted2, err := callerState.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decrypt (caller): %v", err)
	}

	if !bytes.Equal(plaintext2, decrypted2) {
		t.Errorf("Bidirectional decrypted message mismatch: got %q, want %q", decrypted2, plaintext2)
	}

	// Test multiple messages in sequence
	for i := 0; i < 5; i++ {
		msg := []byte(strings.Repeat("test", i+1))
		ct, err := callerState.Encrypt(msg)
		if err != nil {
			t.Fatalf("Encrypt message %d: %v", i, err)
		}
		pt, err := recipientState.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt message %d: %v", i, err)
		}
		if !bytes.Equal(msg, pt) {
			t.Errorf("Message %d mismatch", i)
		}
	}
}

// ============================================================================
// Message Tests
// ============================================================================

func TestMessage_ParseAndType(t *testing.T) {
	cfg := createTestConfig(t, "+1111111111", "Test")
	defer cfg.Close()

	cs, _ := NewCallState(cfg, "+2222222222", true)
	defer cs.Close()
	cs.AKEInit()

	// Create an AKE request
	request, err := cs.AKERequest()
	if err != nil {
		t.Fatalf("AKERequest: %v", err)
	}

	// Parse it
	msg, err := ParseMessage(request)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	defer msg.Close()

	if msg.Type() != MsgAKERequest {
		t.Errorf("Message type = %d, want %d", msg.Type(), MsgAKERequest)
	}

	senderID, err := msg.SenderID()
	if err != nil {
		t.Fatalf("SenderID: %v", err)
	}
	if senderID == "" {
		t.Error("SenderID should not be empty")
	}

	// Verify we can parse the original request bytes again
	msg2, err := ParseMessage(request)
	if err != nil {
		t.Fatalf("ParseMessage (second parse): %v", err)
	}
	defer msg2.Close()

	if msg.Type() != msg2.Type() {
		t.Errorf("Message type mismatch on re-parse: %d vs %d", msg.Type(), msg2.Type())
	}

	senderID2, _ := msg2.SenderID()
	if senderID != senderID2 {
		t.Errorf("Sender ID mismatch on re-parse: %s vs %s", senderID, senderID2)
	}
}

func TestMessage_ByeAndHeartbeat(t *testing.T) {
	cfg := createTestConfig(t, "+1111111111", "Test")
	defer cfg.Close()

	cs, _ := NewCallState(cfg, "+2222222222", true)
	defer cs.Close()
	cs.AKEInit()

	// Test Bye message
	bye, err := cs.CreateByeMessage()
	if err != nil {
		t.Fatalf("CreateByeMessage: %v", err)
	}
	if len(bye) == 0 {
		t.Error("Bye message should not be empty")
	}

	byeMsg, err := ParseMessage(bye)
	if err != nil {
		t.Fatalf("ParseMessage (bye): %v", err)
	}
	defer byeMsg.Close()
	if byeMsg.Type() != MsgBye {
		t.Errorf("Bye message type = %d, want %d", byeMsg.Type(), MsgBye)
	}

	// Test Heartbeat message
	hb, err := cs.CreateHeartbeatMessage()
	if err != nil {
		t.Fatalf("CreateHeartbeatMessage: %v", err)
	}
	if len(hb) == 0 {
		t.Error("Heartbeat message should not be empty")
	}

	hbMsg, err := ParseMessage(hb)
	if err != nil {
		t.Fatalf("ParseMessage (heartbeat): %v", err)
	}
	defer hbMsg.Close()
	if hbMsg.Type() != MsgHeartbeat {
		t.Errorf("Heartbeat message type = %d, want %d", hbMsg.Type(), MsgHeartbeat)
	}
}

// ============================================================================
// Enrollment Tests
// ============================================================================

func TestEnrollment_FullFlow(t *testing.T) {
	// This test validates the full enrollment flow using the shared server config
	phone := "+1555987654"
	name := "Test Enrollment"
	logo := "https://example.com/logo.png"

	// Client creates request
	keys, request, err := CreateEnrollmentRequest(phone, name, logo, 3)
	if err != nil {
		t.Fatalf("CreateEnrollmentRequest: %v", err)
	}
	defer keys.Close()

	if len(request) == 0 {
		t.Error("Request should not be empty")
	}

	// Server processes (using shared test server config)
	response, err := testServerConfig.ProcessEnrollment(request)
	if err != nil {
		t.Fatalf("ProcessEnrollment: %v", err)
	}
	if len(response) == 0 {
		t.Error("Response should not be empty")
	}

	// Client finalizes
	cfg, err := FinalizeEnrollment(keys, response, phone, name, logo)
	if err != nil {
		t.Fatalf("FinalizeEnrollment: %v", err)
	}
	defer cfg.Close()

	// Verify config is usable
	envStr, err := cfg.ToEnv()
	if err != nil {
		t.Fatalf("ToEnv: %v", err)
	}

	if !strings.Contains(envStr, phone) {
		t.Error("Config should contain phone number")
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestErrors_NilHandles(t *testing.T) {
	var cfg *Config
	_, err := cfg.ToEnv()
	if err != ErrInvalidArg {
		t.Errorf("Expected ErrInvalidArg, got %v", err)
	}

	var cs *CallState
	_, err = cs.AKERequest()
	if err != ErrInvalidArg {
		t.Errorf("Expected ErrInvalidArg, got %v", err)
	}
}

func TestErrors_InvalidInput(t *testing.T) {
	cfg := createTestConfig(t, "+1111111111", "Test")
	defer cfg.Close()

	cs, _ := NewCallState(cfg, "+2222222222", true)
	defer cs.Close()
	cs.AKEInit()

	// Empty input
	_, err := cs.AKEResponse(nil)
	if err != ErrInvalidArg {
		t.Errorf("Expected ErrInvalidArg for nil input, got %v", err)
	}

	_, err = cs.AKEResponse([]byte{})
	if err != ErrInvalidArg {
		t.Errorf("Expected ErrInvalidArg for empty input, got %v", err)
	}
}
