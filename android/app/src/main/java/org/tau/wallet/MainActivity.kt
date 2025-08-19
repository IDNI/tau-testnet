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
    }

    private fun setupRuleValidation() {
        etRule.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                validateRuleSyntax(s.toString())
            }
        })
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
        val savedWallets = sharedPreferences.all
        wallets.clear()
        for ((key, value) in savedWallets) {
            wallets[key] = value as String
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
            putString(name, skHex)
            apply()
        }
        loadWallets()
        // Set spinner to the newly saved wallet
        val newPosition = walletAdapter.getPosition(name)
        if (newPosition >= 0) {
            spinnerWallets.setSelection(newPosition)
        }
    }

    private fun loadWallet(name: String) {
        val skHex = wallets[name] ?: return
        val skBytes = skHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        privateKeyBytes = skBytes
        // Assuming the same stub logic for pk generation
        val pk = skBytes // Stub: pk = sk
        val pkHex = pk.joinToString("") { String.format("%02x", it) }
        publicKeyHex = pkHex

        tvPrivKeyHex.text = "Private key (hex): $skHex"
        tvPubKeyHex.text = "Public key (hex): $pkHex"
        // Clear old results
        tvBalance.text = "Balance: -"
        tvHistory.text = "History: -"
        tvResult.text = "Result:"
    }


    private fun deleteSelectedWallet() {
        if (spinnerWallets.selectedItem == null) {
            tvResult.text = "No wallet selected to delete."
            return
        }
        val selectedWalletName = spinnerWallets.selectedItem as String
        with(sharedPreferences.edit()) {
            remove(selectedWalletName)
            apply()
        }
        wallets.remove(selectedWalletName)
        updateWalletSpinner()

        // Clear keys if the deleted wallet was the active one
        if(wallets.isEmpty()){
            privateKeyBytes = null
            publicKeyHex = null
            tvPrivKeyHex.text = "Private key (hex):"
            tvPubKeyHex.text = "Public key (hex):"
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

        // 1. Check for balanced parentheses, brackets, and braces
        val stack = ArrayDeque<Char>()
        val pairs = mapOf(')' to '(', ']' to '[', '}' to '{')
        for (char in rule) {
            when (char) {
                '(', '[', '{' -> stack.addLast(char)
                ')', ']', '}' -> {
                    if (stack.isEmpty() || stack.removeLast() != pairs[char]) {
                        errors.add("Mismatched closing bracket '$char'.")
                    }
                }
            }
        }
        if (stack.isNotEmpty()) {
            errors.add("Unclosed brackets: ${stack.joinToString(", ")}.")
        }

        // 2. Check for invalid characters
        val allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_[]()='&|!<>+-*/%^: \t\n\r"
        for (char in rule) {
            if (char !in allowedChars) {
                errors.add("Invalid character '$char'.")
            }
        }

        // 3. Basic operator checks
        val oneLinRule = rule.lines().joinToString(" ") { it.trim() }
        val tokens = oneLinRule.split("\\s+".toRegex()).filter { it.isNotEmpty() }
        if (tokens.isNotEmpty()) {
            val operators = setOf("&&", "||", "&", "|", "=", "->", "<-", "<->")
            if (operators.contains(tokens.first())) {
                errors.add("Rule cannot start with an operator: '${tokens.first()}'.")
            }
            if (operators.contains(tokens.last())) {
                errors.add("Rule cannot end with an operator: '${tokens.last()}'.")
            }
        }
        
        if (errors.isEmpty()) {
            tvRuleValidationStatus.text = "Valid Syntax"
            tvRuleValidationStatus.setTextColor(getColor(android.R.color.holo_green_dark))
            isRuleValid = true
        } else {
            val errorText = "Invalid Syntax:\n- ${errors.joinToString("\n- ")}"
            tvRuleValidationStatus.text = errorText
            tvRuleValidationStatus.setTextColor(getColor(android.R.color.holo_red_dark))
            isRuleValid = false
        }
    }


    private fun generateKeypair() {
        val random = SecureRandom()
        val ikm = ByteArray(32)
        random.nextBytes(ikm)
        // Stub: Derive a 48-byte private key using SHA-512 truncated to 48 bytes
        val sk = sha512(ikm).copyOfRange(0, 48)
        privateKeyBytes = sk
        // Stub public key equals private key (matches py_ecc_stub behavior)
        val pk = sk
        val pkHex = pk.joinToString("") { String.format("%02x", it) }
        val skHex = sk.joinToString("") { String.format("%02x", it) }
        publicKeyHex = pkHex
        tvPrivKeyHex.text = "Private key (hex): $skHex"
        tvPubKeyHex.text = "Public key (hex): $pkHex"

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
            val sig = sha256(sk + msgHash) // aligns with py_ecc_stub Verify
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
}

