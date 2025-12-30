package io.github.lokingdav.libdia.examples

import io.github.lokingdav.libdia.CallState
import io.github.lokingdav.libdia.DiaConfig
import io.github.lokingdav.libdia.LibDia

/**
 * Example demonstrating a complete call flow with AKE + RUA.
 * Based on the protocol tests from bindings/go/dia_test.go
 */
object CallFlowExample {
    
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size < 2) {
            println("Usage: CallFlowExample <aliceEnvFile> <bobEnvFile>")
            println("Example: CallFlowExample alice.env bob.env")
            println("\nFirst run EnrollmentExample to generate configs")
            return
        }
        
        val aliceEnvFile = args[0]
        val bobEnvFile = args[1]
        
        // Load native library
        System.loadLibrary("dia_jni")
        LibDia.init()
        
        try {
            val aliceEnv = java.io.File(aliceEnvFile).readText()
            val bobEnv = java.io.File(bobEnvFile).readText()
            
            demonstrateCallFlow(aliceEnv, bobEnv)
        } catch (e: Exception) {
            System.err.println("Call flow failed: ${e.message}")
            e.printStackTrace()
            System.exit(1)
        }
    }
    
    private fun demonstrateCallFlow(aliceEnv: String, bobEnv: String) {
        println("=== DIA Call Flow Example ===\n")
        
        // Load configs
        DiaConfig.fromEnv(aliceEnv).use { aliceCfg ->
            DiaConfig.fromEnv(bobEnv).use { bobCfg ->
                
                // Extract phone numbers for demo
                val alicePhone = extractPhone(aliceEnv)
                val bobPhone = extractPhone(bobEnv)
                
                // Create call states
                CallState.create(aliceCfg, bobPhone, isInitiator = true).use { alice ->
                    CallState.create(bobCfg, alicePhone, isInitiator = false).use { bob ->
                        
                        println("Alice calling Bob...")
                        println("Alice: $alicePhone")
                        println("Bob: $bobPhone\n")
                        
                        // === AKE Phase ===
                        println("--- AKE (Authenticated Key Exchange) ---")
                        
                        // Initialize AKE
                        println("1. Initializing AKE...")
                        alice.akeInit()
                        bob.akeInit()
                        
                        // Verify topics match
                        val aliceTopic = alice.akeTopic()
                        val bobTopic = bob.akeTopic()
                        println("   Alice AKE topic: $aliceTopic")
                        println("   Bob AKE topic: $bobTopic")
                        require(aliceTopic == bobTopic) { "AKE topics must match!" }
                        
                        // Step 1: Alice -> Bob (AKE Request)
                        println("\n2. Alice creates AKE request...")
                        val akeReq = alice.akeRequest()
                        println("   Sent: ${akeReq.size} bytes")
                        
                        // Step 2: Bob -> Alice (AKE Response)
                        println("3. Bob processes request and responds...")
                        val akeResp = bob.akeResponse(akeReq)
                        println("   Sent: ${akeResp.size} bytes")
                        
                        // Step 3: Alice -> Bob (AKE Complete)
                        println("4. Alice completes AKE...")
                        val akeComplete = alice.akeComplete(akeResp)
                        println("   Sent: ${akeComplete.size} bytes")
                        
                        // Step 4: Bob finalizes
                        println("5. Bob finalizes AKE...")
                        bob.akeFinalize(akeComplete)
                        println("   ✓ AKE completed")
                        
                        // Verify shared keys match
                        val aliceKey = alice.sharedKey()
                        val bobKey = bob.sharedKey()
                        require(aliceKey.contentEquals(bobKey)) { "Shared keys must match!" }
                        println("   Shared key established: ${aliceKey.size} bytes\n")
                        
                        // === RUA Phase ===
                        println("--- RUA (Remote User Authentication) ---")
                        
                        // Transition to RUA
                        println("6. Transitioning to RUA...")
                        alice.transitionToRua()
                        bob.transitionToRua()
                        
                        // Verify RUA topics match
                        val aliceRuaTopic = alice.currentTopic()
                        val bobRuaTopic = bob.currentTopic()
                        println("   RUA topic: $aliceRuaTopic")
                        require(aliceRuaTopic == bobRuaTopic) { "RUA topics must match!" }
                        
                        // Step 1: Alice -> Bob (RUA Request)
                        println("\n7. Alice creates RUA request...")
                        val ruaReq = alice.ruaRequest()
                        println("   Sent: ${ruaReq.size} bytes")
                        
                        // Step 2: Bob -> Alice (RUA Response)
                        println("8. Bob responds to RUA request...")
                        val ruaResp = bob.ruaResponse(ruaReq)
                        println("   Sent: ${ruaResp.size} bytes")
                        
                        // Step 3: Alice finalizes and gets remote party info
                        println("9. Alice finalizes RUA...")
                        alice.ruaFinalize(ruaResp)
                        println("   ✓ RUA completed")
                        
                        val remoteParty = alice.remoteParty()
                        println("\n   Remote party verified:")
                        println("     Phone: ${remoteParty.phone}")
                        println("     Name: ${remoteParty.name}")
                        println("     Verified: ${remoteParty.verified}\n")
                        
                        // === Double Ratchet Messaging ===
                        println("--- Double Ratchet Messaging ---")
                        
                        // Alice -> Bob
                        println("10. Alice sends encrypted message...")
                        val msg1 = "Hello Bob, this is Alice!"
                        val encrypted1 = alice.encrypt(msg1)
                        println("    Encrypted: \"$msg1\" (${encrypted1.size} bytes)")
                        
                        println("11. Bob receives and decrypts...")
                        val decrypted1 = bob.decrypt(encrypted1)
                        println("    Decrypted: \"$decrypted1\"")
                        require(decrypted1 == msg1) { "Message mismatch!" }
                        println("    ✓ Message verified")
                        
                        // Bob -> Alice
                        println("\n12. Bob sends encrypted response...")
                        val msg2 = "Hi Alice, message received!"
                        val encrypted2 = bob.encrypt(msg2)
                        println("    Encrypted: \"$msg2\" (${encrypted2.size} bytes)")
                        
                        println("13. Alice receives and decrypts...")
                        val decrypted2 = alice.decrypt(encrypted2)
                        println("    Decrypted: \"$decrypted2\"")
                        require(decrypted2 == msg2) { "Message mismatch!" }
                        println("    ✓ Response verified")
                        
                        // === Call Termination ===
                        println("\n--- Call Termination ---")
                        println("14. Alice ends call...")
                        val byeMsg = CallState.bye()
                        println("    Sent BYE message (${byeMsg.size} bytes)")
                        
                        println("\n=== Call Flow Completed Successfully ===")
                    }
                }
            }
        }
    }
    
    private fun extractPhone(envStr: String): String {
        val phoneRegex = """PHONE=([^\n]+)""".toRegex()
        return phoneRegex.find(envStr)?.groupValues?.get(1) ?: "unknown"
    }
}
