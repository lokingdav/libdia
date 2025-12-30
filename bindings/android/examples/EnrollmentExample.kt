package io.github.lokingdav.libdia.examples

import io.github.lokingdav.libdia.DiaConfig
import io.github.lokingdav.libdia.CallState

/**
 * Example demonstrating subscriber enrollment.
 * Based on the enrollment flow from bindings/go/dia_test.go
 */
object EnrollmentExample {
    
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size < 2) {
            println("Usage: EnrollmentExample <phone> <name> [logoUrl]")
            println("Example: EnrollmentExample +1234567890 \"John Doe\" https://example.com/logo.png")
            return
        }
        
        val phone = args[0]
        val name = args[1]
        val logoUrl = if (args.size > 2) args[2] else "https://example.com/logo.png"
        
        // Load native library
        System.loadLibrary("dia_jni")
        
        try {
            performEnrollment(phone, name, logoUrl)
        } catch (e: Exception) {
            System.err.println("Enrollment failed: ${e.message}")
            e.printStackTrace()
            System.exit(1)
        }
    }
    
    private fun performEnrollment(phone: String, name: String, logoUrl: String) {
        println("=== DIA Enrollment Example ===")
        println("Phone: $phone")
        println("Name: $name")
        println("Logo URL: $logoUrl")
        println()
        
        // For this example, we'll generate a test server config
        // In production, the enrollment server would handle this
        println("Generating test server config...")
        val serverConfig = io.github.lokingdav.libdia.LibDia.serverConfigGenerate(30)
        if (serverConfig == 0L) {
            throw Exception("Failed to generate server config")
        }
        
        try {
            // Step 1: Client creates enrollment request
            println("Creating enrollment request...")
            val keysHandle = io.github.lokingdav.libdia.LibDia.enrollmentCreateRequest(
                phone, name, logoUrl, 1
            )
            if (keysHandle == 0L) {
                throw Exception("Failed to create enrollment keys")
            }
            
            try {
                val request = io.github.lokingdav.libdia.LibDia.enrollmentGetRequest(keysHandle)
                println("Enrollment request created (${request.size} bytes)")
                
                // Step 2: Server processes enrollment request
                println("Processing enrollment request...")
                val response = io.github.lokingdav.libdia.LibDia.enrollmentProcess(serverConfig, request)
                println("Enrollment response received (${response.size} bytes)")
                
                // Step 3: Client finalizes enrollment
                println("Finalizing enrollment...")
                val configHandle = io.github.lokingdav.libdia.LibDia.enrollmentFinalize(
                    keysHandle, response, phone, name, logoUrl
                )
                if (configHandle == 0L) {
                    throw Exception("Failed to finalize enrollment")
                }
                
                // Step 4: Serialize config for storage
                DiaConfig(configHandle).use { config ->
                    val envStr = config.toEnv()
                    println("\n✓ Enrollment successful!")
                    println("\nConfig (save this securely):")
                    println("================================")
                    println(envStr)
                    println("================================")
                }
            } finally {
                io.github.lokingdav.libdia.LibDia.enrollmentKeysDestroy(keysHandle)
            }
        } finally {
            io.github.lokingdav.libdia.LibDia.serverConfigDestroy(serverConfig)
        }
    }
}
