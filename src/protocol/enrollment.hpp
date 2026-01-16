#ifndef DIA_PROTOCOL_ENROLLMENT_HPP
#define DIA_PROTOCOL_ENROLLMENT_HPP

#include "../crypto/ecgroup.hpp"
#include "../crypto/bbs.hpp"
#include "../crypto/pke.hpp"
#include "../crypto/doubleratchet.hpp"
#include "callstate.hpp"
#include "accesstoken.hpp"

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>

namespace protocol {

using ecgroup::Bytes;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------
class EnrollmentError : public std::runtime_error {
public:
    explicit EnrollmentError(const std::string& msg) : std::runtime_error(msg) {}
};

// -----------------------------------------------------------------------------
// Ticket types (enrollment naming) - implemented by the access token module.
// -----------------------------------------------------------------------------
using BlindedTicket = accesstoken::BlindedAccessToken;
using Ticket = accesstoken::AccessToken;

// -----------------------------------------------------------------------------
// Client-side keys generated during enrollment
// -----------------------------------------------------------------------------
struct EnrollmentKeys {
    // Subscriber signing keys (BBS for request authentication)
    Bytes subscriber_private_key;
    Bytes subscriber_public_key;
    
    // AMF keys (AMF keygen for accountability)
    Bytes amf_private_key;
    Bytes amf_public_key;
    
    // PKE keys (libsodium sealed box)
    Bytes pke_private_key;
    Bytes pke_public_key;
    
    // Double Ratchet keys (X25519)
    Bytes dr_private_key;
    Bytes dr_public_key;
    
    // Blinded tickets (kept for finalization)
    std::vector<BlindedTicket> blinded_tickets;
};

// -----------------------------------------------------------------------------
// Enrollment Request (client → server)
// -----------------------------------------------------------------------------
struct EnrollmentRequest {
    std::string telephone_number;
    std::string name;
    std::string logo_url;
    
    Bytes nonce;                      // 32 random bytes
    Bytes subscriber_public_key;      // DER-encoded Ed25519 public key
    Bytes amf_public_key;
    Bytes pke_public_key;
    Bytes dr_public_key;
    std::vector<Bytes> blinded_tickets;
    Bytes signature;                  // Ed25519 signature over request
    
    Bytes serialize() const;
    static EnrollmentRequest deserialize(const Bytes& data);
};

// -----------------------------------------------------------------------------
// Enrollment Response (server → client)
// -----------------------------------------------------------------------------
struct EnrollmentResponse {
    std::string enrollment_id;        // Hex-encoded random ID
    Bytes expiration;                 // Serialized timestamp
    Bytes ra_public_key;              // BBS public key (credential issuer)
    Bytes ra_signature;               // BBS signature over enrollment
    Bytes amf_moderator_pk;           // Moderator's AMF public key
    Bytes ticket_verify_key;          // VOPRF verification key
    std::vector<Bytes> evaluated_tickets;
    
    Bytes serialize() const;
    static EnrollmentResponse deserialize(const Bytes& data);
};

// -----------------------------------------------------------------------------
// Server configuration
// -----------------------------------------------------------------------------
struct ServerConfig {
    // Credential Issuance keypair (BBS)
    Bytes ci_private_key;
    Bytes ci_public_key;
    
    // Access Throttling keypair (VOPRF)
    Bytes at_private_key;
    Bytes at_public_key;
    
    // AMF Moderator keypair
    Bytes amf_private_key;
    Bytes amf_public_key;
    
    // Enrollment duration in days
    int enrollment_duration_days = 30;
    
    // Serialize to environment variable format
    std::string to_env_string() const;
    
    // Deserialize from environment variable format
    static ServerConfig from_env_string(const std::string& env_content);
};

// -----------------------------------------------------------------------------
// Delegation (owner-side BBS signature)
// -----------------------------------------------------------------------------

struct Delegation {
    Bytes expiration;  // 8-byte big-endian timestamp (same format as make_expiration)
    Bytes signature;   // BBS signature bytes
};

// -----------------------------------------------------------------------------
// Client-side functions
// -----------------------------------------------------------------------------

// Generate all keys and create enrollment request
// Returns the keys (to be kept by client) and the request (to send to server)
std::pair<EnrollmentKeys, EnrollmentRequest> create_enrollment_request(
    const std::string& telephone_number,
    const std::string& name,
    const std::string& logo_url,
    std::size_t num_tickets = 1
);

// Finalize enrollment after receiving server response
// Returns a ClientConfig ready for use
ClientConfig finalize_enrollment(
    const EnrollmentKeys& keys,
    const EnrollmentResponse& response,
    const std::string& telephone_number,
    const std::string& name,
    const std::string& logo_url
);

// Generate blinded tickets for enrollment
std::vector<BlindedTicket> generate_blinded_tickets(std::size_t count);

// Finalize tickets after server evaluation
std::vector<Ticket> finalize_tickets(
    const std::vector<BlindedTicket>& blinded,
    const std::vector<Bytes>& evaluated
);

// -----------------------------------------------------------------------------
// Server-side functions
// -----------------------------------------------------------------------------

// Process enrollment request and generate response
EnrollmentResponse process_enrollment(
    const ServerConfig& config,
    const EnrollmentRequest& request
);

// Create a delegation signature for a delegate.
// Signs two BBS messages:
//   m1 = H(delegate_pk, expiration, telephone_number)
//   m2 = rules
// Where rules is a length-prefixed serialization of rule strings.
Delegation create_delegation(
    const Bytes& signer_bbs_sk,
    const Bytes& delegate_pk,
    int days_valid,
    const std::string& telephone_number,
    const std::vector<std::string>& rules = {}
);

// Generate expiration timestamp (days from now)
Bytes make_expiration(int days);

// Check if expiration is valid and not expired
bool check_expiry(const Bytes& expiration);

// Verify a ticket using the server's VOPRF verification key
// Returns true if the ticket is valid, false otherwise
bool verify_ticket(
    const Ticket& ticket,
    const Bytes& verification_key
);

} // namespace protocol

#endif // DIA_PROTOCOL_ENROLLMENT_HPP
