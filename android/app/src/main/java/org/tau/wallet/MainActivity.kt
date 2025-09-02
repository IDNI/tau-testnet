package org.tau.wallet

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket
import java.security.SecureRandom
import kotlin.concurrent.thread
import android.content.SharedPreferences
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Spinner
import androidx.appcompat.app.AlertDialog
import java.util.ArrayDeque
import org.tau.wallet.crypto.Bls

class MainActivity : AppCompatActivity() {

    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var tvPrivKeyHex: TextView
    private lateinit var tvPubKeyHex: TextView
    private lateinit var tvBalance: TextView
    private lateinit var tvHistory: TextView
    private lateinit var etRule: EditText
    private lateinit var etTo: EditText
    private lateinit var etAmount: EditText
    private lateinit var tvResult: TextView
    private lateinit var spinnerWallets: Spinner
    private lateinit var tvRuleValidationStatus: TextView

    private var privateKeyBytes: ByteArray? = null
    private var publicKeyHex: String? = null

    private lateinit var sharedPreferences: SharedPreferences
    private val wallets = mutableMapOf<String, String>()
    private lateinit var walletAdapter: ArrayAdapter<String>
    private var isRuleValid = true


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        sharedPreferences = getSharedPreferences("tau_wallet", MODE_PRIVATE)

        etHost = findViewById(R.id.etHost)
        etPort = findViewById(R.id.etPort)
        tvPrivKeyHex = findViewById(R.id.tvPrivKeyHex)
        tvPubKeyHex = findViewById(R.id.tvPubKeyHex)
        tvBalance = findViewById(R.id.tvBalance)
        tvHistory = findViewById(R.id.tvHistory)
        etRule = findViewById(R.id.etRule)
        etTo = findViewById(R.id.etTo)
        etAmount = findViewById(R.id.etAmount)
        tvResult = findViewById(R.id.tvResult)
        spinnerWallets = findViewById(R.id.spinnerWallets)
        tvRuleValidationStatus = findViewById(R.id.tvRuleValidationStatus)

        findViewById<Button>(R.id.btnGenKey).setOnClickListener { generateKeypair() }
        findViewById<Button>(R.id.btnBalance).setOnClickListener { queryBalance() }
        findViewById<Button>(R.id.btnHistory).setOnClickListener { queryHistory() }
        findViewById<Button>(R.id.btnSend).setOnClickListener { sendTx() }
        findViewById<Button>(R.id.btnSaveWallet).setOnClickListener { showSaveWalletDialog() }
        findViewById<Button>(R.id.btnDeleteWallet).setOnClickListener { deleteSelectedWallet() }


        setupWalletSpinner()
        loadWallets()
        setupRuleValidation()
        setupHostPortPersistence()
        loadSavedHostPort()
    }

    private fun setupRuleValidation() {
        etRule.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun afterTextChanged(s: Editable?) {
                validateRuleSyntax(s.toString())
            }
        })
    }

    private fun setupHostPortPersistence() {
        etHost.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun afterTextChanged(s: Editable?) {
                saveHostPort()
            }
        })

        etPort.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun afterTextChanged(s: Editable?) {
                saveHostPort()
            }
        })
    }

    private fun saveHostPort() {
        val host = etHost.text.toString().trim()
        val port = etPort.text.toString().trim()

        with(sharedPreferences.edit()) {
            putString("server_host", host)
            putString("server_port", port)
            apply()
        }
    }

    private fun loadSavedHostPort() {
        val savedHost = sharedPreferences.getString("server_host", "localhost")
        val savedPort = sharedPreferences.getString("server_port", "8080")

        etHost.setText(savedHost)
        etPort.setText(savedPort)
    }

    private fun setupWalletSpinner() {
        walletAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, wallets.keys.toMutableList())
        walletAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerWallets.adapter = walletAdapter

        spinnerWallets.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?, position: Int, id: Long) {
                val selectedWalletName = parent.getItemAtPosition(position) as String
                loadWallet(selectedWalletName)
            }
            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
    }

    private fun loadWallets() {
        // --- One-time migration for old wallet formats ---
        val editor = sharedPreferences.edit()
        var migrationNeeded = false
        sharedPreferences.all.forEach { (key, _) ->
            if (!key.startsWith("wallet_") && key != "server_host" && key != "server_port") {
                val skHex = sharedPreferences.getString(key, null)
                if (skHex != null) {
                    editor.putString("wallet_$key", skHex)
                    editor.remove(key)
                    migrationNeeded = true
                }
            }
        }
        if (migrationNeeded) {
            editor.apply()
        }
        // --- End of migration ---

        val savedWallets = sharedPreferences.all
        wallets.clear()
        for ((key, value) in savedWallets) {
            if (key.startsWith("wallet_")) {
                val walletName = key.substringAfter("wallet_")
                wallets[walletName] = value as String
            }
        }
        updateWalletSpinner()
        if (wallets.isNotEmpty()) {
            spinnerWallets.setSelection(0)
            loadWallet(wallets.keys.first())
        }
    }

    private fun updateWalletSpinner() {
        walletAdapter.clear()
        walletAdapter.addAll(wallets.keys.sorted())
        walletAdapter.notifyDataSetChanged()
    }

    private fun showSaveWalletDialog() {
        if (privateKeyBytes == null) {
            tvResult.text = "Generate a keypair before saving."
            return
        }

        val builder = AlertDialog.Builder(this)
        builder.setTitle("Save Wallet")
        val input = EditText(this)
        input.hint = "Enter wallet name"
        builder.setView(input)

        builder.setPositiveButton("Save") { dialog, _ ->
            val walletName = input.text.toString().trim()
            if (walletName.isNotEmpty()) {
                saveWallet(walletName)
            }
            dialog.dismiss()
        }
        builder.setNegativeButton("Cancel") { dialog, _ -> dialog.cancel() }
        builder.show()
    }

    private fun saveWallet(name: String) {
        val skHex = privateKeyBytes?.joinToString("") { String.format("%02x", it) } ?: return
        with(sharedPreferences.edit()) {
            putString("wallet_$name", skHex)
            apply()
        }
        // Ensure the internal map is updated before refreshing the spinner
        wallets[name] = skHex
        updateWalletSpinner()
        // Set spinner to the newly saved wallet
        val newPosition = walletAdapter.getPosition(name)
        if (newPosition >= 0) {
            spinnerWallets.setSelection(newPosition)
        }
    }

    private fun loadWallet(name: String) {
        val storedHex = wallets[name] ?: return

        // Validate that the stored hex string contains only valid hex characters
        if (!storedHex.matches(Regex("^[0-9a-fA-F]*$"))) {
            tvResult.text = "Error: Invalid wallet data format for '$name'. Contains non-hex characters."
            return
        }

        // Validate that the hex string has even length
        if (storedHex.length % 2 != 0) {
            tvResult.text = "Error: Invalid wallet data format for '$name'. Hex string length must be even."
            return
        }

        try {
            val storedBytes = storedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

            // Handle migration from old 48-byte format to new 32-byte format
            val skBytes = when (storedBytes.size) {
                32 -> storedBytes // Already in new format
                48 -> sha256(storedBytes).also {
                    // Update stored wallet to new format
                    val newSkHex = it.joinToString("") { String.format("%02x", it) }
                    with(sharedPreferences.edit()) {
                        putString("wallet_$name", newSkHex)
                        apply()
                    }
                    wallets[name] = newSkHex
                }
                else -> {
                    tvResult.text = "Error: Invalid wallet format"
                    return
                }
            }

            privateKeyBytes = skBytes
            // Derive 48-byte public key from 32-byte private key (BLS SkToPk via JNI when available)
            val pk = Bls.skToPk(skBytes)
            val pkHex = pk.joinToString("") { String.format("%02x", it) }
            val skHex = skBytes.joinToString("") { String.format("%02x", it) }
            publicKeyHex = pkHex

            tvPrivKeyHex.text = "Private Key (hex, 32 bytes): $skHex"
            tvPubKeyHex.text = "Public Key (hex, 48 bytes, G1 compressed): $pkHex"
            // Clear old results
            tvBalance.text = "BALANCE: -"
            tvHistory.text = "History: -"
            tvResult.text = "Result:"
        } catch (e: Exception) {
            tvResult.text = "Error: Failed to load wallet '$name'. Invalid data format: ${e.message}"
            return
        }
    }


    private fun deleteSelectedWallet() {
        if (spinnerWallets.selectedItem == null) {
            tvResult.text = "No wallet selected to delete."
            return
        }
        val selectedWalletName = spinnerWallets.selectedItem as String
        with(sharedPreferences.edit()) {
            remove("wallet_$selectedWalletName")
            apply()
        }
        wallets.remove(selectedWalletName)
        updateWalletSpinner()

        // Clear keys if the deleted wallet was the active one
        if(wallets.isEmpty()){
            privateKeyBytes = null
            publicKeyHex = null
            tvPrivKeyHex.text = "Private Key (hex, 32 bytes):"
            tvPubKeyHex.text = "Public Key (hex, 48 bytes, G1 compressed):"
        } else {
             spinnerWallets.setSelection(0)
             loadWallet(wallets.keys.first())
        }
    }


    private fun validateRuleSyntax(rule: String) {
        if (rule.isBlank()) {
            tvRuleValidationStatus.text = ""
            isRuleValid = true
            return
        }

        val errors = mutableListOf<String>()

        // 1. Check for balanced parentheses, brackets, and braces (quick structural check)
        val stack = ArrayDeque<Char>()
        val pairs = mapOf(')' to '(', ']' to '[', '}' to '{')
        rule.forEachIndexed { index, char ->
            when (char) {
                '(', '[', '{' -> stack.addLast(char)
                ')', ']', '}' -> {
                    if (stack.isEmpty() || stack.removeLast() != pairs[char]) {
                        errors.add("Mismatched closing bracket '$char' at position ${index + 1}.")
                    }
                }
            }
        }
        if (stack.isNotEmpty()) {
            errors.add("Unclosed brackets: ${stack.joinToString(", ")}.")
        }

        if (errors.isNotEmpty()) {
            displayErrors(errors)
            return
        }

        // 2. Tokenize the rule string using a robust scanning approach
        val tokens = mutableListOf<String>()
        try {
            tokens.addAll(tokenize(rule))
        } catch (e: Exception) {
            errors.add(e.message ?: "An unknown tokenization error occurred.")
            displayErrors(errors)
            return
        }

        // 3. Validate token sequences
        val binaryOperators = setOf(
            "&&", "||", "<->", "->", "<-", "^",
            "=", "!=", "<", ">", "<=", ">=", "!<", "!>", "!<=", "!>=",
            "=_", "!=_", "<_", ">_", "<=_", ">=_", "!<_", "!<=_", "!>_", "!>=_",
            "&", "|", "+", "*", "/", "%", "-"
        )
        val unaryPrefixOperators = setOf("!", "~", "always", "sometimes", "all", "ex")
        val unaryPostfixOperators = setOf("'")
        val allOperators = binaryOperators + unaryPrefixOperators + unaryPostfixOperators + setOf("?", ":")
        val brackets = setOf("(", ")", "[", "]", "{", "}")
        val validKeywords = setOf("tau", "sbf", "console", "ifile", "ofile", "T", "F")
        val operands = tokens.filter { !allOperators.contains(it) && !brackets.contains(it) }

        if (tokens.isNotEmpty()) {
            // Check for invalid start/end of rule
            if (binaryOperators.contains(tokens.first()) || unaryPostfixOperators.contains(tokens.first())) {
                errors.add("Rule cannot start with operator: '${tokens.first()}'.")
            }
            if (binaryOperators.contains(tokens.last()) || unaryPrefixOperators.contains(tokens.last())) {
                errors.add("Rule cannot end with operator: '${tokens.last()}'.")
            }

            // Check sequences
            tokens.forEachIndexed { index, token ->
                val nextToken = tokens.getOrNull(index + 1)
                val isOperand = operands.contains(token)

                if (isOperand) {
                    // Check for consecutive operands
                    if (nextToken != null && operands.contains(nextToken)) {
                        errors.add("Unexpected sequence of operands: '$token $nextToken'.")
                    }
                } else { // It's an operator or bracket
                    // Check for consecutive binary operators
                    if (binaryOperators.contains(token) && nextToken != null && (binaryOperators.contains(nextToken))) {
                        errors.add("Invalid operator sequence: '$token $nextToken'.")
                    }
                }
            }

            // Check for balanced ternary operators
            val qCount = tokens.count { it == "?" }
            val cCount = tokens.count { it == ":" }
            if (qCount != cCount) {
                errors.add("Mismatched ternary operators: $qCount '?' vs $cCount ':' found.")
            }
        }

        if (errors.isEmpty()) {
            tvRuleValidationStatus.text = "Valid Syntax"
            tvRuleValidationStatus.setTextColor(getColor(android.R.color.holo_green_dark))
            isRuleValid = true
        } else {
            displayErrors(errors)
        }
    }

    @Throws(Exception::class)
    private fun tokenize(rule: String): List<String> {
        // Pre-process: remove comments and normalize whitespace
        var remainingRule = rule.lines().joinToString(" ") { it.substringBefore('#') }.trim()

        val tokens = mutableListOf<String>()
        // Define all operators and sort by length to ensure correct matching (e.g., '!=' before '!')
        val operators = listOf(
            "!<=_", "!>=_", "!=_", "<=_", ">=_", "<_", ">_", "!(+)", "&&", "||", "<->", "->", "<-",
            "!=", "!<=", "!>=", "!<", "!>", "=_", "<=", ">=", "!&", "!|", "(+)", "<<", ">>", "&",
            "|", "'", "+", "^", "~", "?", ":", "=", "<", ">", "*", "/", "%", "-", "!", // Added "!"
            "(", ")", "[", "]", "{", "}"
        ).sortedByDescending { it.length }

        val tokenPatterns = listOf(
            "((i|o)\\d+|u|this)\\[(t(-\\d+)?|\\d+)\\]",      // Stream variables
            "#[bB][01]+",                                 // Binary literals
            "#[xX][0-9a-fA-F]+",                         // Hex literals
            "<[a-zA-Z0-9_]+:[a-zA-Z0-9_]+>",             // Uninterpreted constants
            "(always|sometimes|all|ex|tau|sbf|console|ifile|ofile|T|F)", // Keywords
            "[a-zA-Z][0-9]*",                             // Identifiers
            "[0-9]+",                                     // Numeric literals
            operators.joinToString("|") { Regex.escape(it) } // All operators
        )
        val tokenizerRegex = tokenPatterns.joinToString("|").toRegex()

        while (remainingRule.isNotEmpty()) {
            val match = tokenizerRegex.find(remainingRule)
            if (match != null && match.range.first == 0) {
                tokens.add(match.value)
                remainingRule = remainingRule.substring(match.range.last + 1).trimStart()
            } else {
                throw Exception("Unrecognized syntax starting at: '${remainingRule.take(15)}...'")
            }
        }
        return tokens
    }

    private fun displayErrors(errors: List<String>) {
        val errorText = "Invalid Syntax:\n- ${errors.distinct().joinToString("\n- ")}"
        tvRuleValidationStatus.text = errorText
        tvRuleValidationStatus.setTextColor(getColor(android.R.color.holo_red_dark))
        isRuleValid = false
    }

    private fun generateKeypair() {
        val random = SecureRandom()
        val ikm = ByteArray(32)
        random.nextBytes(ikm)
        // Generate 32-byte private key using SHA-256 (matches gen.py approach)
        val sk = sha256(ikm)
        privateKeyBytes = sk
        // Derive 48-byte public key from private key (BLS SkToPk via JNI when available)
        val pk = Bls.skToPk(sk)
        val pkHex = pk.joinToString("") { String.format("%02x", it) }
        val skHex = sk.joinToString("") { String.format("%02x", it) }
        publicKeyHex = pkHex
        tvPrivKeyHex.text = "Private Key (hex, 32 bytes): $skHex"
        tvPubKeyHex.text = "Public Key (hex, 48 bytes, G1 compressed): $pkHex"

        // Deselect spinner to indicate this is a new, unsaved wallet
        spinnerWallets.setSelection(AdapterView.INVALID_POSITION)
    }

    private fun queryBalance() {
        val addr = publicKeyHex ?:  run {
            tvBalance.text = "No wallet loaded."
            return
        }
        val host = etHost.text.toString()
        val port = etPort.text.toString().toIntOrNull() ?: return
        thread {
            val resp = rpc("getbalance $addr\r\n", host, port)
            runOnUiThread { tvBalance.text = resp.trim() }
        }
    }

    private fun queryHistory() {
        val addr = publicKeyHex ?: run {
            tvHistory.text = "No wallet loaded."
            return
        }
        val host = etHost.text.toString()
        val port = etPort.text.toString().toIntOrNull() ?: return
        thread {
            val resp = rpc("history $addr\r\n", host, port)
            runOnUiThread { tvHistory.text = resp.trim() }
        }
    }

    private fun sendTx() {
        val sk = privateKeyBytes ?: run {
            runOnUiThread { tvResult.text = "Error: Private key not generated or wallet not loaded." }
            return
        }
        val senderPk = publicKeyHex ?: run {
            runOnUiThread { tvResult.text = "Error: Public key not generated or wallet not loaded." }
            return
        }

        val ruleInput = etRule.text.toString()
        if (ruleInput.isNotEmpty() && !isRuleValid) {
            runOnUiThread { tvResult.text = "Error: Rule syntax is invalid. Please fix the errors before sending." }
            return
        }

        val rule = ruleInput.lines().joinToString(" ") { it.trim() }
        val to = etTo.text.toString().trim()
        val amountStr = etAmount.text.toString().trim()
        val host = etHost.text.toString()
        val port = etPort.text.toString().toIntOrNull() ?: return

        val operations = mutableMapOf<String, Any>()

        if (rule.isNotEmpty()) {
            operations["0"] = rule
        }

        if (to.isNotEmpty() && amountStr.isNotEmpty()) {
            val amount = amountStr.toLongOrNull()
            if (amount == null || amount < 0) {
                runOnUiThread { tvResult.text = "Error: Invalid amount." }
                return
            }
            val transfer = listOf(listOf(senderPk, to, amount.toString()))
            operations["1"] = transfer
        }

        if (operations.isEmpty()) {
            runOnUiThread { tvResult.text = "Error: No operations specified. Enter a rule or a transfer." }
            return
        }


        thread {
            val seqLine = rpc("getsequence $senderPk\r\n", host, port).trim()
            val seq = if (seqLine.startsWith("SEQUENCE: ")) {
                seqLine.substringAfter(": ").toIntOrNull() ?: 0
            } else {
                val hist = rpc("history $senderPk\r\n", host, port).trim().split('\n')
                if (hist.size > 1) hist.size -1 else 0
            }

            val expiry = (System.currentTimeMillis() / 1000L + 3600).toInt()
            val payloadNoSig = mapOf(
                "sender_pubkey" to senderPk,
                "sequence_number" to seq,
                "expiration_time" to expiry,
                "operations" to operations,
                "fee_limit" to "0"
            )
            val signingJson = canonicalJson(payloadNoSig)
            val msgHash = sha256(signingJson.toByteArray())
            // BLS Sign over SHA-256(canonical_json); uses JNI when available, else stub
            val sig = Bls.sign(sk, msgHash)
            val sigHex = sig.joinToString("") { String.format("%02x", it) }

            val payload = payloadNoSig + mapOf("signature" to sigHex)
            val blob = compactJson(payload)
            val cmd = "sendtx '$blob'\r\n"
            val resp = rpc(cmd, host, port)
            runOnUiThread { tvResult.text = resp.trim() }
        }
    }

    private fun rpc(cmd: String, host: String, port: Int): String {
        return try {
            Socket(host, port).use { socket ->
                val out = PrintWriter(socket.getOutputStream(), true)
                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                out.print(cmd)
                out.flush()
                val buf = CharArray(65536)
                val n = reader.read(buf)
                if (n > 0) String(buf, 0, n) else ""
            }
        } catch (e: Exception) {
            "ERROR: ${e.message}"
        }
    }

    private fun canonicalJson(map: Map<String, Any?>): String {
        // Produce JSON with sorted keys and compact separators
        val keys = map.keys.sorted()
        val parts = keys.map { key ->
            val value = map[key]
            "\"$key\":${toJson(value, sorted = true)}"
        }
        return "{${parts.joinToString(",")}}"
    }

    private fun compactJson(map: Map<String, Any?>): String {
        return toJson(map, sorted = false)
    }

    private fun toJson(value: Any?, sorted: Boolean): String {
        return when (value) {
            null -> "null"
            is String -> "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
            is Number, is Boolean -> value.toString()
            is Map<*, *> -> {
                val entries = if (sorted) value.keys.map { it as String }.sorted() else value.keys.map { it as String }
                val parts = entries.map { k ->
                    val v = value[k]
                    "\"$k\":${toJson(v, sorted)}"
                }
                "{${parts.joinToString(",")}}"
            }
            is List<*> -> {
                val parts = value.map { toJson(it, sorted) }
                "[${parts.joinToString(",")}]"
            }
            else -> "\"$value\""
        }
    }

    private fun sha256(input: ByteArray): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(input)
    }

    private fun sha512(input: ByteArray): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-512")
        return md.digest(input)
    }

    // derivePublicKey removed; use Bls.skToPk instead
}

