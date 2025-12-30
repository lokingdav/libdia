package io.github.lokingdav.libdia.test

import io.github.lokingdav.libdia.*
import org.junit.After
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * DIA protocol tests for Android bindings.
 * Based on the Go binding tests in bindings/go/dia_test.go
 */
class DiaTest {
    
    companion object {
        // Shared server config for all tests (avoids key generation overhead)
        private var testServerConfig: Long = 0
        
        init {
            // Load native library
            System.loadLibrary("dia_jni")
            
            // Initialize DIA library
            LibDia.init()
            
            // Generate test server config
            testServerConfig = LibDia.serverConfigGenerate(30)
            if (testServerConfig == 0L) {
                throw RuntimeException("Failed to generate test server config")
            }
        }
        
        fun cleanup() {
            if (testServerConfig != 0L) {
                LibDia.serverConfigDestroy(testServerConfig)
                testServerConfig = 0
            }
        }
    }
    
    /**
     * Helper to create a test configuration using enrollment flow
     */
    private fun createTestConfig(phone: String, name: String, logoUrl: String = "https://example.com/logo.png"): DiaConfig {
        // Client creates enrollment request
        val keysHandle = LibDia.enrollmentCreateRequest(phone, name, logoUrl, 1)
        assertNotNull(keysHandle, "Failed to create enrollment keys")
        assertTrue(keysHandle != 0L, "Enrollment keys handle should not be null")
        
        try {
            val request = LibDia.enrollmentGetRequest(keysHandle)
            assertNotNull(request, "Failed to get enrollment request")
            
            // Server processes request
            val response = LibDia.enrollmentProcess(testServerConfig, request)
            assertNotNull(response, "Failed to process enrollment")
            
            // Client finalizes enrollment
            val configHandle = LibDia.enrollmentFinalize(keysHandle, response, phone, name, logoUrl)
            assertNotNull(configHandle, "Failed to finalize enrollment")
            assertTrue(configHandle != 0L, "Config handle should not be null")
            
            return DiaConfig(configHandle)
        } finally {
            LibDia.enrollmentKeysDestroy(keysHandle)
        }
    }
    
    // ============================================================================
    // Config Tests
    // ============================================================================
    
    @Test
    fun testConfigEnrollmentFlow() {
        val config = createTestConfig("+1234567890", "Test User")
        config.use {
            // Verify config can be serialized
            val envStr = config.toEnv()
            assertNotNull(envStr)
            assertTrue(envStr.contains("+1234567890"), "Config should contain phone number")
            assertTrue(envStr.contains("Test User"), "Config should contain name")
        }
    }
    
    @Test
    fun testConfigRoundTrip() {
        val config1 = createTestConfig("+1555123456", "Alice")
        config1.use {
            // Serialize
            val envStr = config1.toEnv()
            assertNotNull(envStr)
            
            // Parse back
            DiaConfig.fromEnv(envStr).use { config2 ->
                // Serialize again and compare
                val envStr2 = config2.toEnv()
                assertEquals(envStr, envStr2, "Config round-trip failed")
            }
        }
    }
    
    // ============================================================================
    // CallState Tests
    // ============================================================================
    
    @Test
    fun testCallStateCreation() {
        val config = createTestConfig("+1111111111", "Caller")
        config.use {
            CallState.create(config, "+2222222222", isInitiator = true).use { cs ->
                assertTrue(cs.isCaller(), "Should be caller")
                assertFalse(cs.isRecipient(), "Should not be recipient")
                
                // AKE topic requires akeInit to be called first
                cs.akeInit()
                
                val topic = cs.akeTopic()
                assertNotNull(topic)
                assertTrue(topic.isNotEmpty(), "AKE topic should not be empty")
            }
        }
    }
    
    @Test
    fun testCallStateRecipientRole() {
        val config = createTestConfig("+3333333333", "Recipient")
        config.use {
            CallState.create(config, "+4444444444", isInitiator = false).use { cs ->
                assertFalse(cs.isCaller(), "Should not be caller")
                assertTrue(cs.isRecipient(), "Should be recipient")
            }
        }
    }
    
    // ============================================================================
    // AKE Protocol Tests
    // ============================================================================
    
    @Test
    fun testAkeFullExchange() {
        // Setup caller and recipient configs
        val callerCfg = createTestConfig("+1111111111", "Alice")
        val recipientCfg = createTestConfig("+2222222222", "Bob")
        
        callerCfg.use {
            recipientCfg.use {
                // Create call states
                val callerState = CallState.create(callerCfg, "+2222222222", isInitiator = true)
                val recipientState = CallState.create(recipientCfg, "+1111111111", isInitiator = false)
                
                callerState.use {
                    recipientState.use {
                        // Initialize AKE
                        callerState.akeInit()
                        recipientState.akeInit()
                        
                        // Verify both parties derive the same AKE topic
                        val callerTopic = callerState.akeTopic()
                        val recipientTopic = recipientState.akeTopic()
                        assertEquals(callerTopic, recipientTopic, "AKE topics don't match")
                        assertTrue(callerTopic.isNotEmpty(), "AKE topic should not be empty")
                        
                        // 1. Caller creates request
                        val request = callerState.akeRequest()
                        assertNotNull(request)
                        
                        // 2. Recipient processes request and creates response
                        val response = recipientState.akeResponse(request)
                        assertNotNull(response)
                        
                        // 3. Caller processes response and creates complete
                        val complete = callerState.akeComplete(response)
                        assertNotNull(complete)
                        
                        // 4. Recipient finalizes
                        recipientState.akeFinalize(complete)
                        
                        // Verify shared keys match
                        val callerKey = callerState.sharedKey()
                        val recipientKey = recipientState.sharedKey()
                        assertNotNull(callerKey)
                        assertNotNull(recipientKey)
                        assertTrue(callerKey.contentEquals(recipientKey), "Shared keys do not match")
                        assertTrue(callerKey.isNotEmpty(), "Shared key should not be empty")
                        assertEquals(32, callerKey.size, "Shared key should be 32 bytes")
                        
                        // Verify tickets are present
                        val callerTicket = callerState.ticket()
                        assertNotNull(callerTicket)
                        assertTrue(callerTicket.isNotEmpty(), "Caller ticket should not be empty")
                        
                        val recipientTicket = recipientState.ticket()
                        assertNotNull(recipientTicket)
                        assertTrue(recipientTicket.isNotEmpty(), "Recipient ticket should not be empty")
                        
                        // Verify sender IDs are set
                        val callerSenderID = callerState.senderId()
                        assertNotNull(callerSenderID)
                        assertTrue(callerSenderID.isNotEmpty(), "Caller sender ID should not be empty")
                        
                        val recipientSenderID = recipientState.senderId()
                        assertNotNull(recipientSenderID)
                        assertTrue(recipientSenderID.isNotEmpty(), "Recipient sender ID should not be empty")
                    }
                }
            }
        }
    }
    
    // ============================================================================
    // RUA Protocol Tests
    // ============================================================================
    
    @Test
    fun testRuaAfterAke() {
        // Setup with full AKE exchange first
        val callerCfg = createTestConfig("+1111111111", "Alice")
        val recipientCfg = createTestConfig("+2222222222", "Bob")
        
        callerCfg.use {
            recipientCfg.use {
                val callerState = CallState.create(callerCfg, "+2222222222", isInitiator = true)
                val recipientState = CallState.create(recipientCfg, "+1111111111", isInitiator = false)
                
                callerState.use {
                    recipientState.use {
                        // Complete AKE
                        callerState.akeInit()
                        recipientState.akeInit()
                        val akeReq = callerState.akeRequest()
                        val akeResp = recipientState.akeResponse(akeReq)
                        val akeComplete = callerState.akeComplete(akeResp)
                        recipientState.akeFinalize(akeComplete)
                        
                        // Transition to RUA
                        callerState.transitionToRua()
                        recipientState.transitionToRua()
                        
                        // Verify both parties have the same RUA topic
                        val callerTopic = callerState.currentTopic()
                        val recipientTopic = recipientState.currentTopic()
                        assertEquals(callerTopic, recipientTopic, "RUA topics don't match")
                        assertTrue(callerTopic.isNotEmpty(), "RUA topic should not be empty")
                        
                        // Verify RUA is active
                        assertTrue(callerState.isRuaActive(), "Caller RUA should be active")
                        assertTrue(recipientState.isRuaActive(), "Recipient RUA should be active")
                        
                        // 1. Caller creates RUA request
                        val ruaReq = callerState.ruaRequest()
                        assertNotNull(ruaReq)
                        
                        // 2. Recipient processes and creates response
                        val ruaResp = recipientState.ruaResponse(ruaReq)
                        assertNotNull(ruaResp)
                        
                        // 3. Caller finalizes and gets remote party info
                        callerState.ruaFinalize(ruaResp)
                        
                        val remoteParty = callerState.remoteParty()
                        assertNotNull(remoteParty)
                        assertEquals("+2222222222", remoteParty.phone, "Remote phone should match")
                        assertEquals("Bob", remoteParty.name, "Remote name should match")
                        assertTrue(remoteParty.verified, "Remote party should be verified")
                    }
                }
            }
        }
    }
    
    // ============================================================================
    // Double Ratchet Messaging Tests
    // ============================================================================
    
    @Test
    fun testDoubleRatchetEncryptDecrypt() {
        // Setup complete AKE+RUA first
        val aliceCfg = createTestConfig("+1111111111", "Alice")
        val bobCfg = createTestConfig("+2222222222", "Bob")
        
        aliceCfg.use {
            bobCfg.use {
                val alice = CallState.create(aliceCfg, "+2222222222", isInitiator = true)
                val bob = CallState.create(bobCfg, "+1111111111", isInitiator = false)
                
                alice.use {
                    bob.use {
                        // Complete AKE
                        alice.akeInit()
                        bob.akeInit()
                        val akeReq = alice.akeRequest()
                        val akeResp = bob.akeResponse(akeReq)
                        val akeComplete = alice.akeComplete(akeResp)
                        bob.akeFinalize(akeComplete)
                        
                        // Complete RUA
                        alice.transitionToRua()
                        bob.transitionToRua()
                        val ruaReq = alice.ruaRequest()
                        val ruaResp = bob.ruaResponse(ruaReq)
                        alice.ruaFinalize(ruaResp)
                        
                        // Test bidirectional messaging
                        val msg1 = "Hello Bob!"
                        val encrypted1 = alice.encrypt(msg1)
                        val decrypted1 = bob.decrypt(encrypted1)
                        assertEquals(msg1, decrypted1, "First message should decrypt correctly")
                        
                        val msg2 = "Hello Alice!"
                        val encrypted2 = bob.encrypt(msg2)
                        val decrypted2 = alice.decrypt(encrypted2)
                        assertEquals(msg2, decrypted2, "Second message should decrypt correctly")
                        
                        // Test multiple messages
                        val msg3 = "Message 3"
                        val encrypted3 = alice.encrypt(msg3)
                        val decrypted3 = bob.decrypt(encrypted3)
                        assertEquals(msg3, decrypted3, "Third message should decrypt correctly")
                    }
                }
            }
        }
    }
    
    // ============================================================================
    // Message Parsing Tests
    // ============================================================================
    
    @Test
    fun testMessageParsing() {
        val aliceCfg = createTestConfig("+1111111111", "Alice")
        
        aliceCfg.use {
            val alice = CallState.create(aliceCfg, "+2222222222", isInitiator = true)
            
            alice.use {
                alice.akeInit()
                
                // Test AKE Request message
                val akeReqBytes = alice.akeRequest()
                DiaMessage.deserialize(akeReqBytes).use { msg ->
                    assertEquals(LibDia.MSG_AKE_REQUEST, msg.getType())
                    assertTrue(msg.isAkeRequest)
                    assertFalse(msg.isAkeResponse)
                }
                
                // Test Heartbeat message
                val heartbeatBytes = CallState.heartbeat()
                DiaMessage.deserialize(heartbeatBytes).use { msg ->
                    assertEquals(LibDia.MSG_HEARTBEAT, msg.getType())
                    assertTrue(msg.isHeartbeat)
                    assertFalse(msg.isBye)
                }
                
                // Test BYE message
                val byeBytes = CallState.bye()
                DiaMessage.deserialize(byeBytes).use { msg ->
                    assertEquals(LibDia.MSG_BYE, msg.getType())
                    assertTrue(msg.isBye)
                    assertFalse(msg.isHeartbeat)
                }
            }
        }
    }
}
