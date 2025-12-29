// Package dia provides Go bindings for the DIA (Dynamic Identity Authentication) protocol.
//
// The package provides a high-level API for:
//   - Enrollment: registering users with the system
//   - Call authentication: AKE (Authenticated Key Exchange) and RUA (Right-To-Use Authentication)
//   - Secure messaging: Double Ratchet encrypted communication
//
// Building for development (from source):
//
//	PKG_CONFIG_PATH=/path/to/libdia/build go build
//
// The PKG_CONFIG_PATH should point to the directory containing dia-dev.pc
package dia

/*
#cgo pkg-config: dia
#include <dia/dia_c.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// Error codes
var (
	ErrInvalidArg   = errors.New("dia: invalid argument")
	ErrVerifyFailed = errors.New("dia: verification failed")
	ErrAlloc        = errors.New("dia: allocation failed")
	ErrParse        = errors.New("dia: parse error")
	ErrProtocol     = errors.New("dia: protocol error")
	ErrUnknown      = errors.New("dia: unknown error")
)

// Message types
const (
	MsgUnspecified = C.DIA_MSG_UNSPECIFIED
	MsgAKERequest  = C.DIA_MSG_AKE_REQUEST
	MsgAKEResponse = C.DIA_MSG_AKE_RESPONSE
	MsgAKEComplete = C.DIA_MSG_AKE_COMPLETE
	MsgRUARequest  = C.DIA_MSG_RUA_REQUEST
	MsgRUAResponse = C.DIA_MSG_RUA_RESPONSE
	MsgHeartbeat   = C.DIA_MSG_HEARTBEAT
	MsgBye         = C.DIA_MSG_BYE
)

// one-time init of the underlying library
var initOnce sync.Once

func ensureInit() {
	initOnce.Do(func() {
		C.dia_init()
	})
}

func rcErr(rc C.int) error {
	switch rc {
	case C.DIA_OK:
		return nil
	case C.DIA_ERR_INVALID_ARG:
		return ErrInvalidArg
	case C.DIA_ERR_VERIFY_FAIL:
		return ErrVerifyFailed
	case C.DIA_ERR_ALLOC:
		return ErrAlloc
	case C.DIA_ERR_PARSE:
		return ErrParse
	case C.DIA_ERR_PROTOCOL:
		return ErrProtocol
	default:
		return fmt.Errorf("%w: rc=%d", ErrUnknown, int(rc))
	}
}

// ============================================================================
// Config - Client configuration for DIA protocol
// ============================================================================

// Config represents a DIA client configuration.
type Config struct {
	handle *C.dia_config_t
}

// ConfigFromEnv parses a ClientConfig from environment variable format string.
// The format is KEY=value lines where byte values are hex-encoded.
func ConfigFromEnv(envContent string) (*Config, error) {
	ensureInit()
	cStr := C.CString(envContent)
	defer C.free(unsafe.Pointer(cStr))

	var handle *C.dia_config_t
	rc := C.dia_config_from_env_string(cStr, &handle)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	cfg := &Config{handle: handle}
	runtime.SetFinalizer(cfg, (*Config).Close)
	return cfg, nil
}

// ToEnv serializes the config to environment variable format string.
func (c *Config) ToEnv() (string, error) {
	if c == nil || c.handle == nil {
		return "", ErrInvalidArg
	}
	var out *C.char
	rc := C.dia_config_to_env_string(c.handle, &out)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(out)
	return C.GoString(out), nil
}

// Close releases the config resources.
func (c *Config) Close() {
	if c != nil && c.handle != nil {
		C.dia_config_destroy(c.handle)
		c.handle = nil
	}
}

// ============================================================================
// RemoteParty - Information about the remote party in a call
// ============================================================================

// RemoteParty contains verified information about the other party.
type RemoteParty struct {
	Phone    string
	Name     string
	Logo     string
	Verified bool
}

// ============================================================================
// CallState - State for a single call session
// ============================================================================

// CallState manages the state for a DIA call session.
type CallState struct {
	handle *C.dia_callstate_t
}

// NewCallState creates a new call state for a call session.
// Set outgoing=true for outgoing calls (caller), false for incoming (recipient).
func NewCallState(cfg *Config, phone string, outgoing bool) (*CallState, error) {
	ensureInit()
	if cfg == nil || cfg.handle == nil {
		return nil, ErrInvalidArg
	}

	cPhone := C.CString(phone)
	defer C.free(unsafe.Pointer(cPhone))

	outgoingInt := 0
	if outgoing {
		outgoingInt = 1
	}

	var handle *C.dia_callstate_t
	rc := C.dia_callstate_create(cfg.handle, cPhone, C.int(outgoingInt), &handle)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	cs := &CallState{handle: handle}
	runtime.SetFinalizer(cs, (*CallState).Close)
	return cs, nil
}

// Close releases the call state resources.
func (cs *CallState) Close() {
	if cs != nil && cs.handle != nil {
		C.dia_callstate_destroy(cs.handle)
		cs.handle = nil
	}
}

// AKETopic returns the AKE topic as a hex string.
func (cs *CallState) AKETopic() (string, error) {
	if cs == nil || cs.handle == nil {
		return "", ErrInvalidArg
	}
	var out *C.char
	rc := C.dia_callstate_get_ake_topic(cs.handle, &out)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(out)
	return C.GoString(out), nil
}

// CurrentTopic returns the current active topic as a hex string.
func (cs *CallState) CurrentTopic() (string, error) {
	if cs == nil || cs.handle == nil {
		return "", ErrInvalidArg
	}
	var out *C.char
	rc := C.dia_callstate_get_current_topic(cs.handle, &out)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(out)
	return C.GoString(out), nil
}

// SharedKey returns the shared key (available after AKE completes).
func (cs *CallState) SharedKey() ([]byte, error) {
	if cs == nil || cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_callstate_get_shared_key(cs.handle, &out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// Ticket returns the access ticket.
func (cs *CallState) Ticket() ([]byte, error) {
	if cs == nil || cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_callstate_get_ticket(cs.handle, &out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// SenderID returns the sender ID for this party.
func (cs *CallState) SenderID() (string, error) {
	if cs == nil || cs.handle == nil {
		return "", ErrInvalidArg
	}
	var out *C.char
	rc := C.dia_callstate_get_sender_id(cs.handle, &out)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(out)
	return C.GoString(out), nil
}

// IsCaller returns true if this is an outgoing call (we are the caller).
func (cs *CallState) IsCaller() bool {
	if cs == nil || cs.handle == nil {
		return false
	}
	return C.dia_callstate_iam_caller(cs.handle) == 1
}

// IsRecipient returns true if this is an incoming call (we are the recipient).
func (cs *CallState) IsRecipient() bool {
	if cs == nil || cs.handle == nil {
		return false
	}
	return C.dia_callstate_iam_recipient(cs.handle) == 1
}

// IsRUAActive returns true if the RUA phase is active.
func (cs *CallState) IsRUAActive() bool {
	if cs == nil || cs.handle == nil {
		return false
	}
	return C.dia_callstate_is_rua_active(cs.handle) == 1
}

// RemoteParty returns information about the remote party (populated after RUA).
func (cs *CallState) RemoteParty() (*RemoteParty, error) {
	if cs == nil || cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var out *C.dia_remote_party_t
	rc := C.dia_callstate_get_remote_party(cs.handle, &out)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_remote_party(out)
	return &RemoteParty{
		Phone:    C.GoString(out.phone),
		Name:     C.GoString(out.name),
		Logo:     C.GoString(out.logo),
		Verified: out.verified == 1,
	}, nil
}

// TransitionToRUA updates the current topic to the RUA topic.
func (cs *CallState) TransitionToRUA() error {
	if cs == nil || cs.handle == nil {
		return ErrInvalidArg
	}
	return rcErr(C.dia_callstate_transition_to_rua(cs.handle))
}

// ============================================================================
// AKE Protocol (Authenticated Key Exchange)
// ============================================================================

// AKEInit initializes the AKE state (generates DH keys, computes topic).
func (cs *CallState) AKEInit() error {
	if cs == nil || cs.handle == nil {
		return ErrInvalidArg
	}
	return rcErr(C.dia_ake_init(cs.handle))
}

// AKERequest creates an AKE request message (caller side).
func (cs *CallState) AKERequest() ([]byte, error) {
	if cs == nil || cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_ake_request(cs.handle, &out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// AKEResponse processes an AKE request and creates a response (recipient side).
func (cs *CallState) AKEResponse(request []byte) ([]byte, error) {
	if cs == nil || cs.handle == nil || len(request) == 0 {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_ake_response(cs.handle,
		(*C.uchar)(&request[0]), C.size_t(len(request)),
		&out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// AKEComplete processes an AKE response and creates the completion message (caller side).
// After this, the shared key is computed.
func (cs *CallState) AKEComplete(response []byte) ([]byte, error) {
	if cs == nil || cs.handle == nil || len(response) == 0 {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_ake_complete(cs.handle,
		(*C.uchar)(&response[0]), C.size_t(len(response)),
		&out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// AKEFinalize processes the AKE complete message (recipient side).
// After this, the shared key is computed.
func (cs *CallState) AKEFinalize(complete []byte) error {
	if cs == nil || cs.handle == nil || len(complete) == 0 {
		return ErrInvalidArg
	}
	return rcErr(C.dia_ake_finalize(cs.handle,
		(*C.uchar)(&complete[0]), C.size_t(len(complete))))
}

// ============================================================================
// RUA Protocol (Right-To-Use Authentication)
// ============================================================================

// RUADeriveTopic derives the RUA topic from the shared key.
func (cs *CallState) RUADeriveTopic() (string, error) {
	if cs == nil || cs.handle == nil {
		return "", ErrInvalidArg
	}
	var out *C.char
	rc := C.dia_rua_derive_topic(cs.handle, &out)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(out)
	return C.GoString(out), nil
}

// RUAInit initializes the RTU for RUA phase.
func (cs *CallState) RUAInit() error {
	if cs == nil || cs.handle == nil {
		return ErrInvalidArg
	}
	return rcErr(C.dia_rua_init(cs.handle))
}

// RUARequest creates a RUA request message (caller side).
func (cs *CallState) RUARequest() ([]byte, error) {
	if cs == nil || cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_rua_request(cs.handle, &out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// RUAResponse processes a RUA request and creates a response (recipient side).
// After this, the new shared key is computed and remote party is populated.
func (cs *CallState) RUAResponse(request []byte) ([]byte, error) {
	if cs == nil || cs.handle == nil || len(request) == 0 {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_rua_response(cs.handle,
		(*C.uchar)(&request[0]), C.size_t(len(request)),
		&out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// RUAFinalize processes the RUA response (caller side).
// After this, the new shared key is computed and remote party is populated.
func (cs *CallState) RUAFinalize(response []byte) error {
	if cs == nil || cs.handle == nil || len(response) == 0 {
		return ErrInvalidArg
	}
	return rcErr(C.dia_rua_finalize(cs.handle,
		(*C.uchar)(&response[0]), C.size_t(len(response))))
}

// ============================================================================
// DR Messaging (Double Ratchet encrypted messaging)
// ============================================================================

// Encrypt encrypts a message using the Double Ratchet session (available after RUA).
func (cs *CallState) Encrypt(plaintext []byte) ([]byte, error) {
	if cs == nil || cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var ptPtr *C.uchar
	if len(plaintext) > 0 {
		ptPtr = (*C.uchar)(&plaintext[0])
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_dr_encrypt(cs.handle, ptPtr, C.size_t(len(plaintext)), &out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// Decrypt decrypts a message using the Double Ratchet session (available after RUA).
func (cs *CallState) Decrypt(ciphertext []byte) ([]byte, error) {
	if cs == nil || cs.handle == nil || len(ciphertext) == 0 {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_dr_decrypt(cs.handle,
		(*C.uchar)(&ciphertext[0]), C.size_t(len(ciphertext)),
		&out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// ============================================================================
// Message Handling
// ============================================================================

// Message represents a DIA protocol message.
type Message struct {
	handle *C.dia_message_t
}

// ParseMessage deserializes a protocol message from bytes.
func ParseMessage(data []byte) (*Message, error) {
	ensureInit()
	if len(data) == 0 {
		return nil, ErrInvalidArg
	}
	var handle *C.dia_message_t
	rc := C.dia_message_deserialize((*C.uchar)(&data[0]), C.size_t(len(data)), &handle)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	msg := &Message{handle: handle}
	runtime.SetFinalizer(msg, (*Message).Close)
	return msg, nil
}

// Close releases the message resources.
func (m *Message) Close() {
	if m != nil && m.handle != nil {
		C.dia_message_destroy(m.handle)
		m.handle = nil
	}
}

// Type returns the message type (MsgAKERequest, MsgRUAResponse, etc.)
func (m *Message) Type() int {
	if m.handle == nil {
		return MsgUnspecified
	}
	return int(C.dia_message_get_type(m.handle))
}

// SenderID returns the sender ID from the message.
func (m *Message) SenderID() (string, error) {
	if m.handle == nil {
		return "", ErrInvalidArg
	}
	var out *C.char
	rc := C.dia_message_get_sender_id(m.handle, &out)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(out)
	return C.GoString(out), nil
}

// Topic returns the topic from the message.
func (m *Message) Topic() (string, error) {
	if m.handle == nil {
		return "", ErrInvalidArg
	}
	var out *C.char
	rc := C.dia_message_get_topic(m.handle, &out)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(out)
	return C.GoString(out), nil
}

// CreateByeMessage creates a Bye message for ending a call.
func (cs *CallState) CreateByeMessage() ([]byte, error) {
	if cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_message_create_bye(cs.handle, &out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// CreateHeartbeatMessage creates a Heartbeat message for keep-alive.
func (cs *CallState) CreateHeartbeatMessage() ([]byte, error) {
	if cs.handle == nil {
		return nil, ErrInvalidArg
	}
	var out *C.uchar
	var outLen C.size_t
	rc := C.dia_message_create_heartbeat(cs.handle, &out, &outLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(out)
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// ============================================================================
// Enrollment (Client-side)
// ============================================================================

// EnrollmentKeys holds the keys generated during enrollment (kept by client).
type EnrollmentKeys struct {
	handle *C.dia_enrollment_keys_t
}

// CreateEnrollmentRequest creates an enrollment request with all necessary keys.
// Returns the keys (keep for finalization) and the serialized request to send.
func CreateEnrollmentRequest(phone, name, logoURL string, numTickets int) (*EnrollmentKeys, []byte, error) {
	ensureInit()

	cPhone := C.CString(phone)
	defer C.free(unsafe.Pointer(cPhone))
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cLogo := C.CString(logoURL)
	defer C.free(unsafe.Pointer(cLogo))

	var keysHandle *C.dia_enrollment_keys_t
	var requestData *C.uchar
	var requestLen C.size_t

	rc := C.dia_enrollment_create_request(cPhone, cName, cLogo,
		C.size_t(numTickets), &keysHandle, &requestData, &requestLen)
	if err := rcErr(rc); err != nil {
		return nil, nil, err
	}
	defer C.dia_free_bytes(requestData)

	request := C.GoBytes(unsafe.Pointer(requestData), C.int(requestLen))
	keys := &EnrollmentKeys{handle: keysHandle}
	runtime.SetFinalizer(keys, (*EnrollmentKeys).Close)
	return keys, request, nil
}

// Close releases the enrollment keys resources.
func (ek *EnrollmentKeys) Close() {
	if ek != nil && ek.handle != nil {
		C.dia_enrollment_keys_destroy(ek.handle)
		ek.handle = nil
	}
}

// FinalizeEnrollment finalizes enrollment using the server response.
// Returns a Config ready for use in calls.
func FinalizeEnrollment(keys *EnrollmentKeys, response []byte, phone, name, logoURL string) (*Config, error) {
	if keys == nil || keys.handle == nil || len(response) == 0 {
		return nil, ErrInvalidArg
	}

	cPhone := C.CString(phone)
	defer C.free(unsafe.Pointer(cPhone))
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cLogo := C.CString(logoURL)
	defer C.free(unsafe.Pointer(cLogo))

	var cfgHandle *C.dia_config_t
	rc := C.dia_enrollment_finalize(keys.handle,
		(*C.uchar)(&response[0]), C.size_t(len(response)),
		cPhone, cName, cLogo, &cfgHandle)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	cfg := &Config{handle: cfgHandle}
	runtime.SetFinalizer(cfg, (*Config).Close)
	return cfg, nil
}

// ============================================================================
// Enrollment (Server-side)
// ============================================================================

// ServerConfig holds server-side configuration for processing enrollments.
type ServerConfig struct {
	handle *C.dia_server_config_t
}

// NewServerConfig creates a server configuration for enrollment processing.
func NewServerConfig(ciPrivateKey, ciPublicKey, atPrivateKey, atPublicKey, amfPrivateKey, amfPublicKey []byte, durationDays int) (*ServerConfig, error) {
	ensureInit()

	if len(ciPrivateKey) == 0 || len(ciPublicKey) == 0 ||
		len(atPrivateKey) == 0 || len(atPublicKey) == 0 ||
		len(amfPrivateKey) == 0 || len(amfPublicKey) == 0 {
		return nil, ErrInvalidArg
	}

	var handle *C.dia_server_config_t
	rc := C.dia_server_config_create(
		(*C.uchar)(&ciPrivateKey[0]), C.size_t(len(ciPrivateKey)),
		(*C.uchar)(&ciPublicKey[0]), C.size_t(len(ciPublicKey)),
		(*C.uchar)(&atPrivateKey[0]), C.size_t(len(atPrivateKey)),
		(*C.uchar)(&atPublicKey[0]), C.size_t(len(atPublicKey)),
		(*C.uchar)(&amfPrivateKey[0]), C.size_t(len(amfPrivateKey)),
		(*C.uchar)(&amfPublicKey[0]), C.size_t(len(amfPublicKey)),
		C.int(durationDays), &handle)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	sc := &ServerConfig{handle: handle}
	runtime.SetFinalizer(sc, (*ServerConfig).Close)
	return sc, nil
}

// Close releases the server config resources.
func (sc *ServerConfig) Close() {
	if sc != nil && sc.handle != nil {
		C.dia_server_config_destroy(sc.handle)
		sc.handle = nil
	}
}

// GenerateServerConfig generates a new server configuration with fresh cryptographic keys.
// This is useful for testing or for servers that need to generate their own keys.
func GenerateServerConfig(durationDays int) (*ServerConfig, error) {
	ensureInit()

	var handle *C.dia_server_config_t
	rc := C.dia_server_config_generate(C.int(durationDays), &handle)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	sc := &ServerConfig{handle: handle}
	runtime.SetFinalizer(sc, (*ServerConfig).Close)
	return sc, nil
}

// ProcessEnrollment processes a client enrollment request and returns the response.
func (sc *ServerConfig) ProcessEnrollment(request []byte) ([]byte, error) {
	if sc == nil || sc.handle == nil || len(request) == 0 {
		return nil, ErrInvalidArg
	}

	var responseData *C.uchar
	var responseLen C.size_t
	rc := C.dia_enrollment_process(sc.handle,
		(*C.uchar)(&request[0]), C.size_t(len(request)),
		&responseData, &responseLen)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	defer C.dia_free_bytes(responseData)
	return C.GoBytes(unsafe.Pointer(responseData), C.int(responseLen)), nil
}

// ToEnv serializes the ServerConfig to environment variable format (KEY=value lines).
// Binary values are hex-encoded. This format is suitable for secure storage.
func (sc *ServerConfig) ToEnv() (string, error) {
	if sc == nil || sc.handle == nil {
		return "", ErrInvalidArg
	}

	var envStr *C.char
	rc := C.dia_server_config_to_env_string(sc.handle, &envStr)
	if err := rcErr(rc); err != nil {
		return "", err
	}
	defer C.dia_free_string(envStr)
	return C.GoString(envStr), nil
}

// ServerConfigFromEnv parses a ServerConfig from environment variable format string.
// Expects KEY=value lines with hex-encoded binary values. Comments (lines starting with #)
// and blank lines are ignored.
func ServerConfigFromEnv(envContent string) (*ServerConfig, error) {
	ensureInit()

	if len(envContent) == 0 {
		return nil, ErrInvalidArg
	}

	cEnv := C.CString(envContent)
	defer C.free(unsafe.Pointer(cEnv))

	var handle *C.dia_server_config_t
	rc := C.dia_server_config_from_env_string(cEnv, &handle)
	if err := rcErr(rc); err != nil {
		return nil, err
	}
	sc := &ServerConfig{handle: handle}
	runtime.SetFinalizer(sc, (*ServerConfig).Close)
	return sc, nil
}

// VerifyTicket verifies a ticket using the VOPRF verification key.
// Used by relay server when client consumes a ticket to create a new topic.
// Returns true if the ticket is valid, false otherwise.
func VerifyTicket(ticketData []byte, verifyKey []byte) (bool, error) {
	ensureInit()

	if len(ticketData) == 0 || len(verifyKey) == 0 {
		return false, ErrInvalidArg
	}

	rc := C.dia_verify_ticket(
		(*C.uchar)(&ticketData[0]), C.size_t(len(ticketData)),
		(*C.uchar)(&verifyKey[0]), C.size_t(len(verifyKey)))

	if rc < 0 {
		return false, rcErr(rc)
	}
	return rc == 1, nil
}
