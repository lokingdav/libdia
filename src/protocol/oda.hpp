#ifndef DIA_PROTOCOL_ODA_HPP
#define DIA_PROTOCOL_ODA_HPP

#include "callstate.hpp"
#include "messages.hpp"
#include "../crypto/wallet.hpp"

namespace protocol {

/**
 * ODA Request - Verifier creates an ODA request
 * 
 * Creates an ODA request message with a random nonce and requested attributes.
 * The verifier stores the pending request for later verification.
 * 
 * @param verifier CallState of the verifier (party requesting authentication)
 * @param requested_attributes List of attributes to request
 * @return Serialized ProtocolMessage to send to prover
 */
Bytes oda_request(CallState& verifier, const std::vector<std::string>& requested_attributes);

/**
 * ODA Response - Prover processes request and creates response
 * 
 * Receives the ODA request, uses BasicWallet to create a presentation,
 * and returns the response message.
 * 
 * @param prover CallState of the prover (party providing authentication)
 * @param request_msg The received ODA request message
 * @return Serialized ProtocolMessage to send back to verifier
 */
Bytes oda_response(CallState& prover, const ProtocolMessage& request_msg);

/**
 * ODA Verify - Verifier processes response and verifies presentation
 * 
 * Receives the ODA response, uses BasicWallet to verify the presentation,
 * and stores the verification result in the CallState.
 * 
 * @param verifier CallState of the verifier
 * @param response_msg The received ODA response message
 * @return VerificationResult with verification status and disclosed attributes
 */
crypto::VerificationResult oda_verify(CallState& verifier, const ProtocolMessage& response_msg);

} // namespace protocol

#endif // DIA_PROTOCOL_ODA_HPP
