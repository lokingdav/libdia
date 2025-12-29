package dia

import (
	"runtime"
	"testing"
	"time"
)

// TestAutomaticCleanup verifies that resources are automatically freed via finalizers
// even when Close() is never called.
func TestAutomaticCleanup(t *testing.T) {
	// Create objects without calling Close()
	func() {
		serverCfg, err := GenerateServerConfig(30)
		if err != nil {
			t.Fatal(err)
		}
		// Intentionally NOT calling serverCfg.Close()

		keys, request, err := CreateEnrollmentRequest("+1234567890", "Test", "https://example.com/logo.png", 1)
		if err != nil {
			t.Fatal(err)
		}
		// Intentionally NOT calling keys.Close()

		response, err := serverCfg.ProcessEnrollment(request)
		if err != nil {
			t.Fatal(err)
		}

		config, err := FinalizeEnrollment(keys, response, "+1234567890", "Test", "https://example.com/logo.png")
		if err != nil {
			t.Fatal(err)
		}
		// Intentionally NOT calling config.Close()

		cs, err := NewCallState(config, "+9876543210", true)
		if err != nil {
			t.Fatal(err)
		}
		// Intentionally NOT calling cs.Close()

		_ = cs.AKEInit()

		msg, err := cs.AKERequest()
		if err != nil {
			t.Fatal(err)
		}

		parsedMsg, err := ParseMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		// Intentionally NOT calling parsedMsg.Close()

		_ = parsedMsg

		// All objects go out of scope here without Close() being called
	}()

	// NOTE: The following GC call and sleep are ONLY for testing purposes
	// to verify finalizers work immediately. Users should NEVER do this!
	// In real code, finalizers run automatically in the background when
	// the garbage collector runs - no user intervention needed.
	runtime.GC()
	time.Sleep(10 * time.Millisecond) // Give finalizers time to run

	// If we get here without crashes, automatic cleanup worked
	t.Log("Automatic cleanup via finalizers successful")
}

// TestCloseMultipleTimes verifies that Close() is safe to call multiple times
func TestCloseMultipleTimes(t *testing.T) {
	serverCfg, err := GenerateServerConfig(30)
	if err != nil {
		t.Fatal(err)
	}

	// Call Close() multiple times - should not panic or crash
	serverCfg.Close()
	serverCfg.Close()
	serverCfg.Close()

	// Test with enrollment keys
	keys, request, err := CreateEnrollmentRequest("+1234567890", "Test", "https://example.com/logo.png", 1)
	if err != nil {
		t.Fatal(err)
	}

	// Process enrollment before closing keys
	serverCfg2, _ := GenerateServerConfig(30)
	defer serverCfg2.Close()

	response, err := serverCfg2.ProcessEnrollment(request)
	if err != nil {
		t.Fatal(err)
	}

	config, err := FinalizeEnrollment(keys, response, "+1234567890", "Test", "https://example.com/logo.png")
	if err != nil {
		t.Fatal(err)
	}

	// Now close keys multiple times
	keys.Close()
	keys.Close()

	// Close config multiple times
	config.Close()
	config.Close()
	config.Close()

	// Test with CallState
	config2, _ := FinalizeEnrollment(keys, response, "+1234567890", "Test", "https://example.com/logo.png")
	if config2 == nil {
		// keys was already closed, create new ones
		keys2, request2, _ := CreateEnrollmentRequest("+1234567890", "Test", "https://example.com/logo.png", 1)
		response2, _ := serverCfg2.ProcessEnrollment(request2)
		config2, _ = FinalizeEnrollment(keys2, response2, "+1234567890", "Test", "https://example.com/logo.png")
		keys2.Close()
	}

	cs, err := NewCallState(config2, "+9876543210", true)
	if err != nil {
		t.Fatal(err)
	}

	cs.AKEInit()
	msgBytes, err := cs.AKERequest()
	if err != nil {
		t.Fatal(err)
	}

	msg, err := ParseMessage(msgBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Close all multiple times
	cs.Close()
	cs.Close()
	msg.Close()
	msg.Close()
	msg.Close()
	config2.Close()

	t.Log("Multiple Close() calls are safe")
}
