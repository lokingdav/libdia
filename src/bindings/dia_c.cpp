#include "dia/dia_c.h"
#include "../protocol/callstate.hpp"
#include "../protocol/messages.hpp"
#include "../protocol/ake.hpp"
#include "../protocol/rua.hpp"
#include "../crypto/ecgroup.hpp"
#include "../helpers.hpp"

#include <cstring>
#include <string>
#include <memory>

using namespace protocol;
using ecgroup::Bytes;

/*==============================================================================
 * Internal wrapper structs for opaque handles
 *============================================================================*/

struct dia_config_t {
    ClientConfig config;
};

struct dia_callstate_t {
    std::unique_ptr<CallState> state;
};

struct dia_message_t {
    ProtocolMessage msg;
};

/*==============================================================================
 * Helper functions
 *============================================================================*/

static char* copy_to_c_string(const std::string& str) {
    char* result = new char[str.size() + 1];
    std::memcpy(result, str.c_str(), str.size() + 1);
    return result;
}

static void copy_to_c_bytes(const Bytes& vec, unsigned char** out, size_t* out_len) {
    *out_len = vec.size();
    if (vec.empty()) {
        *out = nullptr;
        return;
    }
    *out = new unsigned char[*out_len];
    std::memcpy(*out, vec.data(), *out_len);
}

/*==============================================================================
 * Init / Utilities
 *============================================================================*/

void dia_init(void) {
    ecgroup::init_pairing();
}

void dia_free_string(char* str) {
    delete[] str;
}

void dia_free_bytes(unsigned char* buf) {
    delete[] buf;
}

void dia_free_remote_party(dia_remote_party_t* rp) {
    if (rp) {
        dia_free_string(rp->phone);
        dia_free_string(rp->name);
        dia_free_string(rp->logo);
        delete rp;
    }
}

/*==============================================================================
 * Config API
 *============================================================================*/

int dia_config_from_env_string(const char* env_content, dia_config_t** out) {
    if (!env_content || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        auto* cfg = new dia_config_t();
        cfg->config = ClientConfig::from_env_string(std::string(env_content));
        *out = cfg;
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PARSE;
    }
}

int dia_config_to_env_string(const dia_config_t* cfg, char** out) {
    if (!cfg || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        std::string env_str = cfg->config.to_env_string();
        *out = copy_to_c_string(env_str);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

void dia_config_destroy(dia_config_t* cfg) {
    delete cfg;
}

/*==============================================================================
 * CallState API
 *============================================================================*/

int dia_callstate_create(const dia_config_t* cfg,
                         const char* phone,
                         int outgoing,
                         dia_callstate_t** out) {
    if (!cfg || !phone || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        auto* cs = new dia_callstate_t();
        cs->state = std::make_unique<CallState>(cfg->config, std::string(phone), outgoing != 0);
        *out = cs;
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

void dia_callstate_destroy(dia_callstate_t* state) {
    delete state;
}

int dia_callstate_get_ake_topic(const dia_callstate_t* state, char** out) {
    if (!state || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        std::string topic = state->state->get_ake_topic();
        *out = copy_to_c_string(topic);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_callstate_get_current_topic(const dia_callstate_t* state, char** out) {
    if (!state || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        std::string topic = state->state->get_current_topic();
        *out = copy_to_c_string(topic);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_callstate_get_shared_key(const dia_callstate_t* state,
                                 unsigned char** out,
                                 size_t* out_len) {
    if (!state || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        copy_to_c_bytes(state->state->shared_key, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_callstate_get_ticket(const dia_callstate_t* state,
                             unsigned char** out,
                             size_t* out_len) {
    if (!state || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        copy_to_c_bytes(state->state->ticket, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_callstate_get_sender_id(const dia_callstate_t* state, char** out) {
    if (!state || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        *out = copy_to_c_string(state->state->sender_id);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_callstate_iam_caller(const dia_callstate_t* state) {
    if (!state) return 0;
    return state->state->iam_caller() ? 1 : 0;
}

int dia_callstate_iam_recipient(const dia_callstate_t* state) {
    if (!state) return 0;
    return state->state->iam_recipient() ? 1 : 0;
}

int dia_callstate_is_rua_active(const dia_callstate_t* state) {
    if (!state) return 0;
    return state->state->is_rua_active() ? 1 : 0;
}

int dia_callstate_get_remote_party(const dia_callstate_t* state,
                                   dia_remote_party_t** out) {
    if (!state || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        auto* rp = new dia_remote_party_t();
        rp->phone = copy_to_c_string(state->state->remote_party.phone);
        rp->name = copy_to_c_string(state->state->remote_party.name);
        rp->logo = copy_to_c_string(state->state->remote_party.logo);
        rp->verified = state->state->remote_party.verified ? 1 : 0;
        *out = rp;
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_callstate_transition_to_rua(dia_callstate_t* state) {
    if (!state) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes rua_topic = derive_rua_topic(*state->state);
        state->state->transition_to_rua(rua_topic);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

/*==============================================================================
 * AKE Protocol
 *============================================================================*/

int dia_ake_init(dia_callstate_t* state) {
    if (!state) return DIA_ERR_INVALID_ARG;
    
    try {
        init_ake(*state->state);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_ake_request(dia_callstate_t* state,
                    unsigned char** out,
                    size_t* out_len) {
    if (!state || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes request = ake_request(*state->state);
        copy_to_c_bytes(request, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PROTOCOL;
    }
}

int dia_ake_response(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len,
                     unsigned char** out,
                     size_t* out_len) {
    if (!state || !msg_data || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes data(msg_data, msg_data + msg_len);
        ProtocolMessage msg = ProtocolMessage::deserialize(data);
        Bytes response = ake_response(*state->state, msg);
        copy_to_c_bytes(response, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PROTOCOL;
    }
}

int dia_ake_complete(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len,
                     unsigned char** out,
                     size_t* out_len) {
    if (!state || !msg_data || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes data(msg_data, msg_data + msg_len);
        ProtocolMessage msg = ProtocolMessage::deserialize(data);
        Bytes complete = ake_complete(*state->state, msg);
        copy_to_c_bytes(complete, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PROTOCOL;
    }
}

int dia_ake_finalize(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len) {
    if (!state || !msg_data) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes data(msg_data, msg_data + msg_len);
        ProtocolMessage msg = ProtocolMessage::deserialize(data);
        ake_finalize(*state->state, msg);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PROTOCOL;
    }
}

/*==============================================================================
 * RUA Protocol
 *============================================================================*/

int dia_rua_derive_topic(const dia_callstate_t* state, char** out) {
    if (!state || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes topic = derive_rua_topic(*state->state);
        std::string topic_hex = dia::utils::bytes_to_hex(topic);
        *out = copy_to_c_string(topic_hex);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_rua_init(dia_callstate_t* state) {
    if (!state) return DIA_ERR_INVALID_ARG;
    
    try {
        init_rtu(*state->state);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_rua_request(dia_callstate_t* state,
                    unsigned char** out,
                    size_t* out_len) {
    if (!state || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes request = rua_request(*state->state);
        copy_to_c_bytes(request, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PROTOCOL;
    }
}

int dia_rua_response(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len,
                     unsigned char** out,
                     size_t* out_len) {
    if (!state || !msg_data || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes data(msg_data, msg_data + msg_len);
        ProtocolMessage msg = ProtocolMessage::deserialize(data);
        Bytes response = rua_response(*state->state, msg);
        copy_to_c_bytes(response, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PROTOCOL;
    }
}

int dia_rua_finalize(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len) {
    if (!state || !msg_data) return DIA_ERR_INVALID_ARG;
    
    try {
        Bytes data(msg_data, msg_data + msg_len);
        ProtocolMessage msg = ProtocolMessage::deserialize(data);
        rua_finalize(*state->state, msg);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PROTOCOL;
    }
}

/*==============================================================================
 * Message Handling
 *============================================================================*/

int dia_message_deserialize(const unsigned char* data,
                            size_t len,
                            dia_message_t** out) {
    if (!data || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        auto* m = new dia_message_t();
        Bytes bytes(data, data + len);
        m->msg = ProtocolMessage::deserialize(bytes);
        *out = m;
        return DIA_OK;
    } catch (...) {
        return DIA_ERR_PARSE;
    }
}

void dia_message_destroy(dia_message_t* msg) {
    delete msg;
}

int dia_message_get_type(const dia_message_t* msg) {
    if (!msg) return DIA_MSG_UNSPECIFIED;
    return static_cast<int>(msg->msg.type);
}

int dia_message_get_sender_id(const dia_message_t* msg, char** out) {
    if (!msg || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        *out = copy_to_c_string(msg->msg.sender_id);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_message_get_topic(const dia_message_t* msg, char** out) {
    if (!msg || !out) return DIA_ERR_INVALID_ARG;
    
    try {
        *out = copy_to_c_string(msg->msg.topic);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_message_create_bye(const dia_callstate_t* state,
                           unsigned char** out,
                           size_t* out_len) {
    if (!state || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        ProtocolMessage bye = create_bye_message(
            state->state->sender_id,
            state->state->get_current_topic()
        );
        Bytes serialized = bye.serialize();
        copy_to_c_bytes(serialized, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_message_create_heartbeat(const dia_callstate_t* state,
                                 unsigned char** out,
                                 size_t* out_len) {
    if (!state || !out || !out_len) return DIA_ERR_INVALID_ARG;
    
    try {
        ProtocolMessage hb = create_heartbeat_message(
            state->state->sender_id,
            state->state->get_current_topic()
        );
        Bytes serialized = hb.serialize();
        copy_to_c_bytes(serialized, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

/*==============================================================================
 * DR Messaging
 *============================================================================*/

int dia_dr_encrypt(dia_callstate_t* state,
                   const unsigned char* plaintext,
                   size_t plaintext_len,
                   unsigned char** out,
                   size_t* out_len) {
    if (!state || !plaintext || !out || !out_len) return DIA_ERR_INVALID_ARG;
    if (!state->state->dr_session) return DIA_ERR_PROTOCOL;
    
    try {
        Bytes pt(plaintext, plaintext + plaintext_len);
        Bytes ct = state->state->dr_session->encrypt(pt);
        copy_to_c_bytes(ct, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}

int dia_dr_decrypt(dia_callstate_t* state,
                   const unsigned char* ciphertext,
                   size_t ciphertext_len,
                   unsigned char** out,
                   size_t* out_len) {
    if (!state || !ciphertext || !out || !out_len) return DIA_ERR_INVALID_ARG;
    if (!state->state->dr_session) return DIA_ERR_PROTOCOL;
    
    try {
        Bytes ct(ciphertext, ciphertext + ciphertext_len);
        Bytes pt = state->state->dr_session->decrypt(ct);
        copy_to_c_bytes(pt, out, out_len);
        return DIA_OK;
    } catch (...) {
        return DIA_ERR;
    }
}
