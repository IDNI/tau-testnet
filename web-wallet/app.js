// Using global variables from CDN scripts
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// --- State ---
let socket = null;
let currentKeyPair = null;
let isConnected = false;
let savedWallets = {}; // name -> {priv: hex, pub: hex}

// --- DOM Elements ---
const hostInput = document.getElementById('host');
const portInput = document.getElementById('port');
const btnConnect = document.getElementById('btn-connect');
const statusDiv = document.getElementById('connection-status');
const connectionInfo = document.getElementById('connection-info');

const panels = {
    wallet: document.getElementById('wallet-panel'),
    info: document.getElementById('info-panel'),
    tx: document.getElementById('tx-panel')
};

const btnGenerate = document.getElementById('btn-generate');
const btnImport = document.getElementById('btn-import');
const importArea = document.getElementById('import-area');
const importSkInput = document.getElementById('import-sk');
const btnConfirmImport = document.getElementById('btn-confirm-import');
const walletDisplay = document.getElementById('wallet-display');
const pubKeyInput = document.getElementById('pubkey');
const privKeyInput = document.getElementById('privkey');
const btnRevealSk = document.getElementById('btn-reveal-sk');

const statBalance = document.getElementById('stat-balance');
const statSequence = document.getElementById('stat-sequence');
const btnRefresh = document.getElementById('btn-refresh');

const btnSend = document.getElementById('btn-send');
const txRecipient = document.getElementById('tx-recipient');
const btnRefreshAccounts = document.getElementById('btn-refresh-accounts');
const knownAccountsList = document.getElementById('known-accounts');

const txAmount = document.getElementById('tx-amount');
const txRule = document.getElementById('tx-rule');
const ruleValidationStatus = document.getElementById('rule-validation-status');
const btnRandomRule = document.getElementById('btn-random-rule');

// Wallet Management DOM
const walletSelect = document.getElementById('wallet-select');
const btnDeleteWallet = document.getElementById('btn-delete-wallet');
const saveWalletArea = document.getElementById('save-wallet-area');
const walletNameInput = document.getElementById('wallet-name');
const btnSaveWallet = document.getElementById('btn-save-wallet');
const btnShowSave = document.getElementById('btn-show-save');

const logsDiv = document.getElementById('logs');
const btnClearLogs = document.getElementById('btn-clear-logs');

const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// --- Initialization ---
function init() {
    log("Web Wallet initialized.");

    // Event Listeners
    btnConnect.addEventListener('click', toggleConnection);
    btnGenerate.addEventListener('click', generateKey);
    btnImport.addEventListener('click', () => {
        importArea.style.display = 'block';
        saveWalletArea.style.display = 'none';
        // walletDisplay.style.display = 'none'; // Keep display visible if we have one
    });
    btnConfirmImport.addEventListener('click', importKey);
    btnRevealSk.addEventListener('click', () => {
        if (privKeyInput.type === 'password') {
            privKeyInput.type = 'text';
            btnRevealSk.textContent = 'Hide';
        } else {
            privKeyInput.type = 'password';
            btnRevealSk.textContent = 'Reveal';
        }
    });

    // Copy buttons
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const targetId = e.target.dataset.target;
            const el = document.getElementById(targetId);
            if (el && el.value) {
                navigator.clipboard.writeText(el.value);
                log(`Copied ${targetId} to clipboard.`);
            }
        });
    });

    btnRefresh.addEventListener('click', refreshInfo);
    btnSend.addEventListener('click', onSendTransaction);
    btnClearLogs.addEventListener('click', () => logsDiv.innerHTML = '');
    if (btnRefreshAccounts) btnRefreshAccounts.addEventListener('click', refreshKnownAccounts);

    // Rule Logic
    txRule.addEventListener('input', () => validateRuleSyntax(txRule.value));
    btnRandomRule.addEventListener('click', () => {
        const rule = generateRandomTauRule();
        txRule.value = rule;
        validateRuleSyntax(rule);
    });

    // Wallet Mangement Listeners
    loadSavedWallets();
    walletSelect.addEventListener('change', onWalletSelect);
    btnShowSave.addEventListener('click', () => saveWalletArea.style.display = 'block');
    btnSaveWallet.addEventListener('click', saveCurrentWallet);
    btnDeleteWallet.addEventListener('click', deleteSelectedWallet);

    // Tabs
    // Tabs - Handled by Bootstrap data-bs-toggle attributes
}

// --- WebSocket Logic ---
function toggleConnection() {
    if (isConnected) {
        if (socket) socket.close();
        return;
    }

    const host = hostInput.value;
    const port = portInput.value;
    const url = `ws://${host}:${port}`;

    log(`Connecting to ${url}...`);
    btnConnect.disabled = true;

    try {
        socket = new WebSocket(url);

        socket.onopen = () => {
            log("WebSocket Open. Sending Handshake...");
            // Handshake
            socket.send("hello version=1");
        };

        socket.onmessage = (event) => {
            const msg = event.data;
            log(`RECV: ${msg}`, 'recv');

            // Handle Handshake Response
            if (!isConnected && msg.startsWith("ok version=1")) {
                isConnected = true;
                statusDiv.textContent = "Connected";
                statusDiv.classList.replace("disconnected", "connected");
                btnConnect.textContent = "Disconnect";
                btnConnect.disabled = false;
                enablePanels(true);

                connectionInfo.textContent = `Connected to node at ${url} (${msg})`;

                // Auto refresh if key exists
                if (currentKeyPair) {
                    refreshInfo();
                }
                // Refresh accounts on connect
                refreshKnownAccounts();
            } else if (!isConnected && msg.startsWith("error")) {
                log("Handshake Error. Closing.");
                socket.close();
            } else if (isConnected) {
                // Determine what command this might be for based on context?
                // For simplified wallet, logs are enough for now.
                // We could parse getbalance responses etc.
                handleServerResponse(msg);
            }
        };

        socket.onclose = () => {
            log("Disconnected.");
            isConnected = false;
            statusDiv.textContent = "Disconnected";
            statusDiv.classList.replace("connected", "disconnected");
            btnConnect.textContent = "Connect";
            btnConnect.disabled = false;
            enablePanels(false);
            connectionInfo.textContent = "";
            socket = null;
        };

        socket.onerror = (err) => {
            log("WebSocket Error", "error");
            console.error(err);
        };

    } catch (e) {
        log(`Connection failed: ${e.message}`, "error");
        btnConnect.disabled = false;
    }
}

function enablePanels(enabled) {
    Object.values(panels).forEach(p => {
        if (enabled) p.classList.remove('disabled');
        else p.classList.add('disabled');
    });
}

async function sendRpc(command) {
    if (!socket || !isConnected) {
        log("Not connected.", "error");
        return;
    }
    log(`SEND: ${command}`, 'sent');
    socket.send(command);
    // Simple wait/lock mechanism could be added here if we wanted request/response matching
}

function handleServerResponse(msg) {
    // Basic Parsing of common responses
    if (msg.startsWith("BALANCE: ")) {
        const bal = msg.split(":")[1].trim();
        statBalance.textContent = bal;
    } else if (msg.startsWith("SEQUENCE: ")) {
        const seq = msg.split(":")[1].trim();
        statSequence.textContent = seq;
    } else if (msg.startsWith("ACCOUNTS: ")) {
        try {
            const jsonStr = msg.substring(10);
            const accounts = JSON.parse(jsonStr);
            updateKnownAccounts(accounts);
        } catch (e) {
            log("Error parsing accounts list: " + e.message, "error");
        }
    } else if (msg.startsWith("[")) {
        // Handle raw JSON list from getallaccounts
        try {
            const accounts = JSON.parse(msg);
            updateKnownAccounts(accounts);
        } catch (e) {
            log("Error parsing raw accounts list: " + e.message, "error");
        }
    }
}

function refreshKnownAccounts() {
    sendRpc("getallaccounts");
}

function updateKnownAccounts(accounts) {
    knownAccountsList.innerHTML = ''; // Clear
    if (!accounts || !Array.isArray(accounts)) return;

    accounts.forEach(acc => {
        const opt = document.createElement('option');
        opt.value = acc;
        knownAccountsList.appendChild(opt);
    });
    log(`Refreshed ${accounts.length} known accounts.`);
}

// Expose for debugging
window.saveCurrentWallet = saveCurrentWallet;
window.loadSavedWallets = loadSavedWallets;
window.currentKeyPair = currentKeyPair; // Expose keypair too


// --- Crypto & Wallet Logic ---

function generateKey() {
    try {
        const privKey = bls.utils.randomPrivateKey();
        const pubKey = bls.getPublicKey(privKey);

        setWallet(privKey, pubKey);
        log("New Keypair Generated.");
    } catch (e) {
        log(`Error generating key: ${e.message}`, "error");
    }
}

function importKey() {
    const hex = importSkInput.value.trim();
    if (!hex) return;
    try {
        const privKey = hexToBytes(hex);
        if (privKey.length !== 32) throw new Error("Private key must be 32 bytes");

        const pubKey = bls.getPublicKey(privKey);
        setWallet(privKey, pubKey);

        importSkInput.value = "";
        importArea.style.display = "none";
        log("Key Imported.");
    } catch (e) {
        log(`Import failed: ${e.message}`, "error");
    }
}

function setWallet(privKey, pubKey) {
    // Ensure keys are Uint8Array
    const privBytes = privKey instanceof Uint8Array ? privKey : new Uint8Array(privKey);
    const pubBytes = pubKey instanceof Uint8Array ? pubKey : new Uint8Array(pubKey);

    currentKeyPair = {
        priv: privBytes,
        pub: pubBytes
    };

    privKeyInput.value = bytesToHex(privBytes);
    pubKeyInput.value = bytesToHex(pubBytes);

    walletDisplay.style.display = 'block';

    if (isConnected) refreshInfo();
}

function refreshInfo() {
    if (!currentKeyPair) return;
    const pubHex = bytesToHex(currentKeyPair.pub);

    // Get Balance
    sendRpc(`getbalance ${pubHex}`);

    // Get Sequence
    sendRpc(`getsequence ${pubHex}`);
}




async function onSendTransaction() {
    if (!currentKeyPair) {
        log("No wallet loaded.", "error");
        return;
    }
    if (!isConnected) {
        log("Not connected to node.", "error");
        return;
    }

    const recipient = txRecipient.value.trim();
    // Strict recipient check moved below to allow rule-only txs without recipient if needed (or just rule + empty amount)
    // Amount should be string to handle large ints if needed, but for now value is fine
    // The backend expects strings in the list
    const amountVal = txAmount.value;

    // Check for rule existence again (hoisted from below)
    const ruleInputPreCheck = txRule.value.trim();

    // Relax validation:
    // If Rule is present, Recipient and Amount are NOT strictly required (unless logic below enforces transfer).
    // If Rule is NOT present, Recipient and Amount ARE required.

    if (!ruleInputPreCheck) {
        if (!recipient) {
            log("Recipient required for transfer.", "error");
            return;
        }
        if (!amountVal) {
            log("Amount required for transfer.", "error");
            return;
        }
    } else {
        // Rule is present. 
        // We still surely need a recipient if the user INTENDS to transfer?
        // But logic below handles that: `if (recipient && amountVal && ...)`
        // So we can skip strict checks here.
    }
    // Get sequence
    let seq = parseInt(statSequence.textContent);
    if (isNaN(seq)) {
        seq = 0; // Default or maybe we should fail?
        // Ideally we should have fetched it.
        log("Warning: Using sequence 0 (balance info might be stale)", "warn");
    }

    const senderPub = bytesToHex(currentKeyPair.pub);

    // Construct Operations
    const ops = {};

    // Prepare Rule Input first to check existence
    // const ruleInput = txRule.value.trim(); // Removed, using pre-check

    // 1. Transfer Logic
    // User Requirement: If amount is 0 and rule is present, don't send the amount (transfer op).
    const amountNum = parseFloat(amountVal);
    const shouldSendTransfer = recipient && amountVal && (amountNum !== 0 || !ruleInputPreCheck);

    if (shouldSendTransfer) {
        // "1" is transfer: [[from, to, amount]]
        ops["1"] = [[senderPub, recipient, amountVal.toString()]];
    }

    // 2. Rule Logic
    if (ruleInputPreCheck) {
        if (!validateRuleSyntax(ruleInputPreCheck)) {
            log("Invalid Rule Syntax. Correct it before sending.", "error");
            return;
        }
        ops["0"] = ruleInputPreCheck.split('\n').map(l => l.trim()).join(' ');
    }

    if (Object.keys(ops).length === 0) {
        log("Nothing to send. Specify recipient+amount OR a rule.", "error");
        return;
    }


    // Payload for signing
    const payload = {
        "sender_pubkey": senderPub,
        "sequence_number": seq, // Use current sequence (as expected by backend)
        "expiration_time": Math.floor(Date.now() / 1000) + 300, // 5 mins
        "operations": ops,
        "fee_limit": "0"
    };

    try {
        const canonicalJson = canonicalize(payload);
        const msgBytes = new TextEncoder().encode(canonicalJson);
        const msgHash = sha256(msgBytes); // Hash before signing to match valid server approach
        const sig = bls.sign(msgHash, currentKeyPair.priv);

        const fullTx = {
            ...payload,
            "signature": bytesToHex(sig)
        };

        const cmd = "sendtx " + JSON.stringify(fullTx);
        sendRpc(cmd);
        log("Transaction sent.", "sent");

    } catch (e) {
        log("Error signing/sending tx: " + e.message, "error");
        console.error(e);
    }
}

// Helper to match Python's json.dumps(sort_keys=True, separators=(',', ':'))
function canonicalize(obj) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
        return JSON.stringify(obj);
    }
    const keys = Object.keys(obj).sort();
    let str = '{';
    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (i > 0) str += ',';
        str += JSON.stringify(key) + ':' + canonicalize(obj[key]);
    }
    str += '}';
    return str;
}

function validateRuleSyntax(rule) {
    if (!rule || !rule.trim()) {
        ruleValidationStatus.textContent = "";
        return true; // Empty rule is skipped, not invalid
    }
    const errors = [];

    // 1. Check brackets
    const stack = [];
    const pairs = { ')': '(', ']': '[', '}': '{' };
    for (let char of rule) {
        if (['(', '[', '{'].includes(char)) {
            stack.push(char);
        } else if ([')', ']', '}'].includes(char)) {
            if (stack.length === 0 || stack.pop() !== pairs[char]) {
                errors.push(`Mismatched closing bracket '${char}'.`);
            }
        }
    }
    if (stack.length > 0) errors.push(`Unclosed brackets: ${stack.join(', ')}.`);

    // 2. Check invalid chars
    const allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_[]()='&|!<>+-*/%^: \t\n\r{}#?,.";
    for (let char of rule) {
        if (!allowedChars.includes(char)) {
            errors.push(`Invalid character '${char}'.`);
        }
    }

    // 3. Basic operator checks
    const tokens = rule.trim().split(/\s+/).filter(t => t);
    const operators = new Set(["&&", "||", "&", "|", "=", "->", "<-", "<->"]);
    if (tokens.length > 0) {
        if (operators.has(tokens[0])) errors.push(`Rule cannot start with operator: '${tokens[0]}'.`);
        if (operators.has(tokens[tokens.length - 1])) errors.push(`Rule cannot end with operator: '${tokens[tokens.length - 1]}'.`);
    }

    if (errors.length === 0) {
        ruleValidationStatus.textContent = "Valid syntax";
        ruleValidationStatus.style.color = "green";
        return true;
    } else {
        ruleValidationStatus.textContent = "Invalid Syntax: " + errors.join("; ");
        ruleValidationStatus.style.color = "red";
        return false;
    }
}

function generateRandomTauRule() {
    // Generate using stream indices beyond the pre-defined rules.
    const RESERVED_MAX_IDX = 4;
    const outIdx = (RESERVED_MAX_IDX + 1) + Math.floor(Math.random() * 10); // o5..o14
    const bit = Math.floor(Math.random() * 2);

    // Keep this intentionally simple: constant boolean on an unused output stream.
    const rule = `always (o${outIdx}[t] = { #b${bit} }:bv[1]).`;
    return rule;
}

// --- Wallet Management Functions ---


function loadSavedWallets() {
    try {
        const stored = localStorage.getItem('tau_saved_wallets');
        if (stored) {
            savedWallets = JSON.parse(stored);
        }
    } catch (e) {
        console.error("Failed to load wallets", e);
    }
    updateWalletList();
}

function updateWalletList() {
    // Clear options except first
    while (walletSelect.options.length > 1) {
        walletSelect.remove(1);
    }

    Object.keys(savedWallets).forEach(name => {
        const opt = document.createElement('option');
        opt.value = name;
        opt.textContent = name;
        walletSelect.appendChild(opt);
    });
}

function onWalletSelect() {
    const name = walletSelect.value;
    if (!name) {
        btnDeleteWallet.disabled = true;
        return;
    }

    // Switch to selected wallet
    const wallet = savedWallets[name];
    if (wallet) {
        try {
            const privKey = hexToBytes(wallet.priv);
            const pubKey = bls.getPublicKey(privKey);
            setWallet(privKey, pubKey);
            btnDeleteWallet.disabled = false;
            log(`Switched to wallet: ${name}`);
        } catch (e) {
            log("Error loading wallet key: " + e.message, "error");
        }
    }
}

function saveCurrentWallet() {
    if (!currentKeyPair) {
        log("No wallet to save.", "error");
        return;
    }
    const name = walletNameInput.value.trim();
    if (!name) {
        log("Please enter a wallet name.", "error");
        return;
    }

    if (savedWallets[name] && !confirm(`Overwrite wallet "${name}"?`)) {
        return;
    }

    savedWallets[name] = {
        priv: bytesToHex(currentKeyPair.priv),
        pub: bytesToHex(currentKeyPair.pub)
    };

    localStorage.setItem('tau_saved_wallets', JSON.stringify(savedWallets));

    updateWalletList();
    walletSelect.value = name; // Select it
    btnDeleteWallet.disabled = false;

    walletNameInput.value = "";
    saveWalletArea.style.display = "none";
    log(`Wallet "${name}" saved.`);
}

function deleteSelectedWallet() {
    const name = walletSelect.value;
    if (!name || !savedWallets[name]) return;

    if (confirm(`Delete wallet "${name}"?`)) {
        delete savedWallets[name];
        localStorage.setItem('tau_saved_wallets', JSON.stringify(savedWallets));
        updateWalletList();
        walletSelect.value = "";
        btnDeleteWallet.disabled = true;
        log(`Wallet "${name}" deleted.`);
    }
}

// --- Utils ---
function log(msg, type = 'info') {
    const div = document.createElement('div');
    div.classList.add('log-entry', type);

    const time = document.createElement('span');
    time.classList.add('time');
    time.textContent = new Date().toLocaleTimeString();

    div.appendChild(time);
    div.appendChild(document.createTextNode(msg));

    logsDiv.appendChild(div);
    logsDiv.scrollTop = logsDiv.scrollHeight;
}

init();
