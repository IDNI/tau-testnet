package org.tau.wallet

import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
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
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import androidx.appcompat.app.AlertDialog
import java.util.ArrayDeque
import org.tau.wallet.crypto.Bls
import org.json.JSONArray

import com.google.android.material.tabs.TabLayout
import android.view.View
import android.widget.LinearLayout

class MainActivity : AppCompatActivity() {

    private lateinit var actHost: AutoCompleteTextView
    private lateinit var etPort: EditText
    private lateinit var tvPrivKeyHex: TextView
    private lateinit var tvPubKeyHex: TextView
    private lateinit var tvBalance: TextView
    private lateinit var tvHistory: TextView
    private lateinit var etRule: EditText
    private lateinit var actTo: AutoCompleteTextView
    private lateinit var etAmount: EditText
    private lateinit var etCustomOps: EditText

    private lateinit var etCustomOps: EditText
    private lateinit var tabLayoutTx: TabLayout
    private lateinit var layoutTransfer: LinearLayout
    private lateinit var layoutRule: LinearLayout
    private lateinit var layoutCustom: LinearLayout

    private lateinit var tvResult: TextView
    private lateinit var actWallets: AutoCompleteTextView
    // cbRandomRule removed
    private lateinit var tvRuleValidationStatus: TextView

    private var privateKeyBytes: ByteArray? = null
    private var publicKeyHex: String? = null
    private val secureRandom = SecureRandom()

    private lateinit var sharedPreferences: SharedPreferences
    private val wallets = mutableMapOf<String, String>()
    private lateinit var walletAdapter: ArrayAdapter<String>
    private var isRuleValid = true
    private var selectedWalletName: String? = null


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        sharedPreferences = getSharedPreferences("tau_wallet", MODE_PRIVATE)

        actHost = findViewById(R.id.actHost)
        setupHostDropdown()
        etPort = findViewById(R.id.etPort)
        tvPrivKeyHex = findViewById(R.id.tvPrivKeyHex)
        tvPubKeyHex = findViewById(R.id.tvPubKeyHex)
        tvBalance = findViewById(R.id.tvBalance)
        tvHistory = findViewById(R.id.tvHistory)
        etRule = findViewById(R.id.etRule)
        actTo = findViewById(R.id.actTo)
        setupRecipientValidation()
        etAmount = findViewById(R.id.etAmount)
        etCustomOps = findViewById(R.id.etCustomOps)
        
        tabLayoutTx = findViewById(R.id.tabLayoutTx)
        layoutTransfer = findViewById(R.id.layoutTransfer)
        layoutRule = findViewById(R.id.layoutRule)
        layoutCustom = findViewById(R.id.layoutCustom)
        
        tvResult = findViewById(R.id.tvResult)
        actWallets = findViewById(R.id.actWallets)
        // cbRandomRule removed
        tvRuleValidationStatus = findViewById(R.id.tvRuleValidationStatus)
        
        setupTabs()

        findViewById<Button>(R.id.btnGenerateRule).setOnClickListener { 
             etRule.setText(generateRandomTauRule()) 
        }
        findViewById<Button>(R.id.btnFetchPeers).setOnClickListener { 
             queryAllAccounts(verbose = true) 
        }

        findViewById<Button>(R.id.btnGenKey).setOnClickListener { generateKeypair() }
        findViewById<Button>(R.id.btnBalance).setOnClickListener { queryBalance() }
        findViewById<Button>(R.id.btnHistory).setOnClickListener { queryHistory() }
        findViewById<Button>(R.id.btnSend).setOnClickListener { sendTx() }
        findViewById<Button>(R.id.btnSaveWallet).setOnClickListener { showSaveWalletDialog() }
        findViewById<Button>(R.id.btnDeleteWallet).setOnClickListener { deleteSelectedWallet() }


        setupWalletDropdown()
        loadWallets()
        setupRuleValidation()
        try {
            Bls.isAvailable()
        } catch (e: IllegalStateException) {
            tvResult.text = "Error: ${e.message}"
        }
    }

    private fun setupRuleValidation() {
        etRule.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                validateRuleSyntax(s.toString())
            }
        }

    private fun setupTabs() {
        tabLayoutTx.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab?) {
                updateTabVisibility(tab?.position ?: 0)
            }
            override fun onTabUnselected(tab: TabLayout.Tab?) {}
            override fun onTabReselected(tab: TabLayout.Tab?) {}
        })
        // Initialize
        updateTabVisibility(0)
    }

    private fun updateTabVisibility(position: Int) {
        layoutTransfer.visibility = if (position == 0) View.VISIBLE else View.GONE
        layoutRule.visibility = if (position == 1) View.VISIBLE else View.GONE
        layoutCustom.visibility = if (position == 2) View.VISIBLE else View.GONE
    })
    }

    private fun setupWalletDropdown() {
        walletAdapter = ArrayAdapter(this, com.google.android.material.R.layout.mtrl_auto_complete_simple_item, wallets.keys.toMutableList())
        actWallets.setAdapter(walletAdapter)
        actWallets.onItemClickListener = AdapterView.OnItemClickListener { parent, _, position, _ ->
            val name = parent.getItemAtPosition(position) as String
            selectWallet(name)
        }
    }

    private fun loadWallets(preselect: String? = null) {
        val savedWallets = sharedPreferences.all
        wallets.clear()
        for ((key, value) in savedWallets) {
            wallets[key] = value as String
        }
        updateWalletDropdown()

        if (wallets.isEmpty()) {
            selectedWalletName = null
            actWallets.setText("", false)
            return
        }

        val desired = preselect
            ?: selectedWalletName?.takeIf { wallets.containsKey(it) }
            ?: wallets.keys.sorted().first()

        selectWallet(desired)
    }

    private fun updateWalletDropdown() {
        walletAdapter.clear()
        walletAdapter.addAll(wallets.keys.sorted())
        walletAdapter.notifyDataSetChanged()
    }

    private fun selectWallet(name: String) {
        selectedWalletName = name
        actWallets.setText(name, false)
        loadWallet(name)
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
        val sk = privateKeyBytes ?: run {
            tvResult.text = "Error: No private key to save."
            return
        }
        if (sk.size != 32) {
            tvResult.text = "Error: Private key must be 32 bytes before saving."
            return
        }
        val skHex = bytesToHex(sk)
        with(sharedPreferences.edit()) {
            putString(name, skHex)
            apply()
        }
        loadWallets(preselect = name)
    }

    private fun loadWallet(name: String) {
        val skHex = wallets[name] ?: return
        val skBytes = try {
            hexToBytes(skHex)
        } catch (e: IllegalArgumentException) {
            tvResult.text = "Error loading wallet '$name': ${e.message}"
            return
        }

        if (skBytes.size != 32) {
            tvResult.text = "Error loading wallet '$name': Expected 32-byte private key, found ${skBytes.size} bytes. Please regenerate or re-import this wallet."
            return
        }

        try {
            val pkBytes = Bls.skToPk(skBytes)
            val normalizedSkHex = bytesToHex(skBytes)
            val pkHex = bytesToHex(pkBytes)

            privateKeyBytes = skBytes
            publicKeyHex = pkHex

            tvPrivKeyHex.text = normalizedSkHex
            tvPubKeyHex.text = pkHex
            tvBalance.text = "Balance: -"
            tvHistory.text = "History: -"
            tvResult.text = "Loaded wallet '$name'."
        } catch (e: Exception) {
            tvResult.text = "Error loading wallet '$name': ${e.message}"
        }
        queryAllAccounts()
    }
    
    private fun queryAllAccounts(verbose: Boolean = false) {
        val host = actHost.text.toString()
        val port = etPort.text.toString().toIntOrNull() ?: return
        thread {
            val resp = rpc("getallaccounts\r\n", host, port).trim()
            if (verbose) {
                 runOnUiThread { tvResult.text = "Fetch Peers Response:\n$resp" }
            }
            if (resp.startsWith("[")) {
                try {
                    val jsonArray = JSONArray(resp)
                    val accounts = mutableListOf<String>()
                    for (i in 0 until jsonArray.length()) {
                        accounts.add(jsonArray.getString(i))
                    }
                    val myHeader = publicKeyHex
                    accounts.remove(myHeader) // remove self if present
                    
                    if (accounts.isNotEmpty()) {
                        runOnUiThread {
                            val adapter = ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, accounts)
                            actTo.setAdapter(adapter)
                            if (verbose) {
                                actTo.showDropDown()
                                tvResult.append("\n\nFound ${accounts.size} peers.")
                            }
                        }
                    } else if (verbose) {
                        runOnUiThread { tvResult.append("\n\nNo other peers found.") }
                    }
                } catch (e: Exception) {
                    if (verbose) {
                        runOnUiThread { tvResult.append("\n\nJSON Parse Error: ${e.message}") }
                    }
                }
            } else if (verbose) {
                 runOnUiThread { tvResult.append("\n\nError: Unexpected response format.") }
            }
        }
    }


    private fun deleteSelectedWallet() {
        val name = selectedWalletName
            ?: actWallets.text?.toString()?.trim()?.takeIf { it.isNotEmpty() }

        if (name == null || !wallets.containsKey(name)) {
            tvResult.text = "No wallet selected to delete."
            return
        }

        with(sharedPreferences.edit()) {
            remove(name)
            apply()
        }
        wallets.remove(name)
        updateWalletDropdown()

        // Clear keys if the deleted wallet was the active one
        if (wallets.isEmpty()) {
            privateKeyBytes = null
            publicKeyHex = null
            selectedWalletName = null
            actWallets.setText("", false)
            tvPrivKeyHex.text = "-"
            tvPubKeyHex.text = "-"
        } else {
            loadWallets()
        }
    }


    private fun setupHostDropdown() {
        val hosts = listOf("10.0.2.2", "testnet.tau.net", "127.0.0.1")
        val adapter = ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, hosts)
        actHost.setAdapter(adapter)
    }

    private fun setupRecipientValidation() {
        actTo.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val input = s.toString().trim()
                if (input.isNotEmpty() && !isValidHexKey(input)) {
                    actTo.error = "Invalid format: Must be 96-char hex string (BLS PK)"
                } else {
                    actTo.error = null
                }
            }
        })
    }
    
    // Checks for 96 hex characters (BLS public key size)
    private fun isValidHexKey(hex: String): Boolean {
        return hex.length == 96 && hex.matches(Regex("^[0-9a-fA-F]+$"))
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
        val allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_[]()='&|!<>+-*/%^: \t\n\r{}#?,."
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
            tvRuleValidationStatus.text = "Valid syntax"
            tvRuleValidationStatus.setTextColor(getColor(R.color.tau_success))
            isRuleValid = true
        } else {
            val errorText = "Invalid Syntax:\n- ${errors.joinToString("\n- ")}"
            tvRuleValidationStatus.text = errorText
            tvRuleValidationStatus.setTextColor(getColor(R.color.tau_error))
            isRuleValid = false
        }
    }


    private fun generateKeypair() {
        try {
            val (sk, pk) = generateKeypairBytes()
            privateKeyBytes = sk
            val skHex = bytesToHex(sk)
            val pkHex = bytesToHex(pk)
            publicKeyHex = pkHex
            tvPrivKeyHex.text = skHex
            tvPubKeyHex.text = pkHex

            // Clear wallet selection to indicate this is a new, unsaved wallet
            selectedWalletName = null
            actWallets.setText("", false)
            tvBalance.text = "Balance: -"
            tvHistory.text = "History: -"
            tvResult.text = "Generated new keypair."
        } catch (e: Exception) {
            tvResult.text = "Error generating keypair: ${e.message}"
        }
    }

    private fun generateKeypairBytes(): Pair<ByteArray, ByteArray> {
        while (true) {
            val candidateSk = ByteArray(32)
            secureRandom.nextBytes(candidateSk)
            if (candidateSk.all { it == 0.toByte() }) {
                continue
            }
            try {
                val pk = Bls.skToPk(candidateSk)
                return candidateSk to pk
            } catch (_: IllegalArgumentException) {
                // Out-of-range secret key, try again.
            }
        }
    }

    private fun queryBalance() {
        val addr = publicKeyHex ?:  run {
            tvBalance.text = "No wallet loaded."
            return
        }
        val host = actHost.text.toString()
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
        val host = actHost.text.toString()
        val port = etPort.text.toString().toIntOrNull() ?: return
        thread {
            val resp = rpc("history $addr\r\n", host, port)
            
            // Extract potential peers from history (heuristically)
            val peers = mutableSetOf<String>()
            val regex = Regex("[0-9a-fA-F]{96}") // Match BLS public keys
            regex.findAll(resp).forEach { match ->
                 val key = match.value
                 if (key != addr) { // Don't include self
                     peers.add(key)
                 }
            }
            
            runOnUiThread { 
                tvHistory.text = resp.trim()
                if (peers.isNotEmpty()) {
                    val adapter = ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, peers.toList())
                    actTo.setAdapter(adapter)
                }
            }
        }
    }

    private fun sendTx() {
        val sk = privateKeyBytes ?: run {
            tvResult.text = "Error: Private key not generated or wallet not loaded."
            return
        }
        if (sk.size != 32) {
            tvResult.text = "Error: Private key must be 32 bytes. Please regenerate or reload your wallet."
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
        // cbRandomRule logic removed, rule is now fully user controlled via etRule
        
        val to = actTo.text.toString().trim()
        val amountStr = etAmount.text.toString().trim()
        val host = actHost.text.toString()
        val port = etPort.text.toString().toIntOrNull() ?: return

        val operations = mutableMapOf<String, Any>()

        // Determine active tab
        val selectedTabPos = tabLayoutTx.selectedTabPosition
        
        // Logic: Only process inputs from the visible tab? 
        // OR process all valid inputs? 
        // Web wallet processes all valid inputs. But typical UI implies only visible.
        // Let's stick to visible for clarity, or loosely coupled.
        // We'll process ALL present fields because user might switch tabs to "add" more ops.
        // BUT for Transfer amount, if tab is invalid/hidden, maybe ignore?
        // Actually, let's keep it simple: Read all fields. If empty, ignore.
        
        if (rule.isNotEmpty()) {
            operations["0"] = rule
        }

        val customOpsInput = etCustomOps.text.toString()
        if (customOpsInput.isNotEmpty()) {
            val lines = customOpsInput.lines()
            for (line in lines) {
                if (line.isBlank()) continue
                val parts = line.split(":", limit = 2)
                if (parts.size != 2) {
                     runOnUiThread { tvResult.text = "Error: Invalid custom op format '$line'. Use Key:Value" }
                     return
                }
                val keyStr = parts[0].trim()
                val valStr = parts[1].trim()
                
                val kInt = keyStr.toIntOrNull()
                if (kInt == null) {
                    runOnUiThread { tvResult.text = "Error: Custom op key '$keyStr' must be an integer." }
                    return
                }
                if (kInt < 5) {
                    runOnUiThread { tvResult.text = "Error: Custom op key '$keyStr' is reserved (must be >= 5)." }
                    return
                }
                operations[keyStr] = valStr
            }
        }
        
        // Transfer Logic
        // In Web Wallet, we require amount if no Rule.
        // In Android, similar logic.
        // If Transfer tab is active, strict check on Amount?
        // Let's follow Web Wallet logic: "If rule/custom present, amount is optional (unless entered)".
        
        val hasOtherOps = operations.isNotEmpty()
        
        if (to.isNotEmpty()) {
             // If amount is specified, use it.
             // If not specified, and we have other ops, maybe amount 0?
             // But valid integer parsing handles standard cases.
             if (amountStr.isNotEmpty()) {
                 val amount = amountStr.toLongOrNull()
                 if (amount == null || amount < 0) {
                     runOnUiThread { tvResult.text = "Error: Invalid amount." }
                     return
                 }
                 val transfer = listOf(listOf(senderPk, to, amount.toString()))
                 operations["1"] = transfer
             } else if (!hasOtherOps) {
                 // No amount, no other ops -> Error
                 runOnUiThread { tvResult.text = "Error: Amount required." }
                 return
             }
        } else if (!hasOtherOps) {
             // No To, no other ops
             runOnUiThread { tvResult.text = "Error: Recipient or Rule/Custom Op required." }
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
            val signingBytes = signingJson.toByteArray()
            val msgHash = sha256(signingBytes)
            val sig = try {
                Bls.sign(sk, msgHash)
            } catch (e: Exception) {
                runOnUiThread { tvResult.text = "Error signing transaction: ${e.message}" }
                return@thread
            }
            val sigHex = bytesToHex(sig)

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
            is String -> {
                val sb = StringBuilder("\"")
                for (c in value) {
                    when (c) {
                        '\\' -> sb.append("\\\\")
                        '"' -> sb.append("\\\"")
                        '\n' -> sb.append("\\n")
                        '\r' -> sb.append("\\r")
                        '\t' -> sb.append("\\t")
                        '\b' -> sb.append("\\b")
                        '\u000C' -> sb.append("\\f")
                        else -> if (c.code < 32) {
                            sb.append(String.format("\\u%04x", c.code))
                        } else {
                            sb.append(c)
                        }
                    }
                }
                sb.append("\"")
                sb.toString()
            }
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

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02x", it) }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        if (clean.isEmpty()) {
            return ByteArray(0)
        }
        if (clean.length % 2 != 0) {
            throw IllegalArgumentException("Hex string must contain an even number of characters.")
        }
        val result = ByteArray(clean.length / 2)
        var i = 0
        while (i < clean.length) {
            val byteValue = try {
                clean.substring(i, i + 2).toInt(16)
            } catch (e: NumberFormatException) {
                throw IllegalArgumentException("Hex string contains invalid characters.", e)
            }
            result[i / 2] = byteValue.toByte()
            i += 2
        }
        return result
    }

    private fun sha256(input: ByteArray): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(input)
    }
    private fun generateRandomTauRule(): String {
        // o5..o14
        val outIdx = 5 + secureRandom.nextInt(10)
        
        val exprs = listOf(
            "(i1[t] & i2[t] | { #b0 }:bv)",
            "(i3[t] | i4[t] | { #b0 }:bv)",
            "((i1[t] | { #b0 }:bv)')",
            "((i1[t] | i2[t]) & (i3[t] | { 170 }:bv))",
            "((i4[t] | { 66 }:bv)' | (i1[t] & i2[t]))",
            "(((i1[t] | i2[t]) & i3[t]) | { #b0 }:bv)",
            "(((i1[t] & i2[t] | { #b0 }:bv) | (i3[t] | i4[t] | { #b0 }:bv)))"
        )
        val expr = exprs[secureRandom.nextInt(exprs.size)]
        
        val shape = secureRandom.nextInt(4)
        return when (shape) {
            0 -> "always (o$outIdx[t] = $expr)."
            1 -> "always (($expr != { #b0 }:bv) ? o$outIdx[t] = $expr : o$outIdx[t] = ($expr)')."
            2 -> "always (($expr = { #b0 }:bv) ? o$outIdx[t] = $expr : o$outIdx[t] = ($expr)')."
            else -> {
                val bit = secureRandom.nextInt(2)
                "always (o$outIdx[t] = { #b$bit }:bv)."
            }
        }
    }
}

