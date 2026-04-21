// Using global variables from CDN scripts
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// --- State ---
let socket = null;
let currentKeyPair = null;
let isConnected = false;
let savedWallets = {}; // name -> {priv: hex, pub: hex}
let pendingSequence = null; // Track local sequence to prevent 'expected 1 got 0' on rapid sends

const DEFAULT_RULE_BV_WIDTH = 16;
const MAX_TAU_TRANSFER_AMOUNT = (1 << DEFAULT_RULE_BV_WIDTH) - 1;

// --- DOM Elements ---
const hostInput = document.getElementById('host');
const portInput = document.getElementById('port');
const btnConnect = document.getElementById('btn-connect');
const statusDiv = document.getElementById('connection-status');
const connectionInfo = document.getElementById('connection-info');

const panels = {
    wallet: document.getElementById('wallet-panel'),
    addressBook: document.getElementById('address-book-panel'),
    info: document.getElementById('info-panel'),
    tx: document.getElementById('tx-panel')
};

// Address Book DOM
const contactNameInput = document.getElementById('contact-name');
const contactPubkeyInput = document.getElementById('contact-pubkey');
const btnSaveContact = document.getElementById('btn-save-contact');
const contactsListDiv = document.getElementById('contacts-list');
let addressBook = {}; // name -> pubkey hex

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
const btnGetState = document.getElementById('btn-get-state');

const btnSend = document.getElementById('btn-send');
const txRecipient = document.getElementById('tx-recipient');
const btnRefreshAccounts = document.getElementById('btn-refresh-accounts');
const knownAccountsList = document.getElementById('known-accounts-menu'); // UPDATED for Dropdown

const txAmount = document.getElementById('tx-amount');
const txRule = document.getElementById('tx-rule');
const txCustom = document.getElementById('tx-custom'); // New element
const ruleValidationStatus = document.getElementById('rule-validation-status');
const customValidationStatus = document.getElementById('custom-validation-status');
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
const btnCopyLogs = document.getElementById('btn-copy-logs');

const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// --- CodeMirror Editors ---
let ruleEditor = null;
let customEditor = null;

// --- Custom Confirm Modal ---
let confirmModalInstance = null;
let confirmPromiseResolve = null;

function customConfirm(message) {
    if (!confirmModalInstance) {
        const el = document.getElementById('confirmModal');
        if (el) {
            confirmModalInstance = new bootstrap.Modal(el);
            document.getElementById('btn-confirm-action').addEventListener('click', () => {
                if (confirmPromiseResolve) confirmPromiseResolve(true);
                confirmPromiseResolve = null;
                confirmModalInstance.hide();
            });
            el.addEventListener('hidden.bs.modal', () => {
                if (confirmPromiseResolve) {
                    confirmPromiseResolve(false);
                    confirmPromiseResolve = null;
                }
            });
        } else {
            // Fallback
            return Promise.resolve(window.confirm(message));
        }
    }

    return new Promise(resolve => {
        document.getElementById('confirmModalBody').textContent = message;
        confirmPromiseResolve = resolve;
        confirmModalInstance.show();
    });
}

// --- Initialization ---
function init() {
    log("Web Wallet initialized.");

    // Initialize CodeMirror Editors
    if (txRule) {
        ruleEditor = CodeMirror.fromTextArea(txRule, {
            mode: "simple",
            theme: "material-ocean",
            lineNumbers: true,
            lineWrapping: true,
            indentUnit: 4,
            viewportMargin: Infinity
        });
        // Make sure it sizes correctly when unhidden
        document.querySelectorAll('button[data-bs-toggle="tab"]').forEach(tabBtn => {
            tabBtn.addEventListener('shown.bs.tab', function (e) {
                if (ruleEditor) ruleEditor.refresh();
                if (customEditor) customEditor.refresh();
            });
        });
    }

    if (txCustom) {
        customEditor = CodeMirror.fromTextArea(txCustom, {
            mode: "simple",
            theme: "material-ocean",
            lineNumbers: true,
            lineWrapping: true,
            indentUnit: 4,
            viewportMargin: Infinity
        });
    }

    // Event Listeners
    btnConnect.addEventListener('click', toggleConnection);
    btnGenerate.addEventListener('click', generateKey);
    btnImport.addEventListener('click', () => {
        importArea.style.display = 'block';
        saveWalletArea.style.display = 'none';
        // walletDisplay.style.display = 'none'; // Keep display visible if we have one
    });
    btnConfirmImport.addEventListener('click', importKey);
    btnRevealSk.addEventListener('click', async (e) => {
        e.preventDefault();
        if (privKeyInput.type === 'password') {
            const confirmed = await customConfirm("Warning: Anyone with access to your screen can see your private key. Are you sure you want to reveal it?");
            if (confirmed) {
                privKeyInput.type = 'text';
                btnRevealSk.textContent = 'Hide';
            }
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
    if (btnGetState) btnGetState.addEventListener('click', () => sendRpc('gettaustate'));
    btnSend.addEventListener('click', onSendTransaction);
    btnClearLogs.addEventListener('click', () => logsDiv.innerHTML = '');
    if (btnCopyLogs) {
        btnCopyLogs.addEventListener('click', () => {
            if (logsDiv.innerText.trim()) {
                navigator.clipboard.writeText(logsDiv.innerText);
                log("Copied logs to clipboard.", "success");
            }
        });
    }
    if (btnRefreshAccounts) btnRefreshAccounts.addEventListener('click', refreshKnownAccounts);

    if (txAmount) {
        txAmount.min = "0";
        txAmount.max = String(MAX_TAU_TRANSFER_AMOUNT);
        txAmount.step = "1";
    }

    // Rule Logic
    ruleEditor.on('change', () => validateRuleSyntax(ruleEditor.getValue()));
    btnRandomRule.addEventListener('click', () => {
        const rule = generateRandomTauRule();
        ruleEditor.setValue(rule);
        validateRuleSyntax(rule);
    });

    // Wallet and Address Book Management Listeners
    loadSavedWallets();
    loadAddressBook();
    walletSelect.addEventListener('change', onWalletSelect);
    btnShowSave.addEventListener('click', () => saveWalletArea.style.display = 'block');
    btnSaveWallet.addEventListener('click', saveCurrentWallet);
    btnDeleteWallet.addEventListener('click', deleteSelectedWallet);
    btnSaveContact.addEventListener('click', saveContact);

    // Tabs
    // Tabs - Handled by Bootstrap data-bs-toggle attributes
}

// --- WebSocket Logic ---
let connectionAttempts = [];
let connectionIndex = 0;

function toggleConnection() {
    if (isConnected) {
        if (socket) socket.close();
        return;
    }

    const host = hostInput.value;
    const port = portInput.value;

    // Determine the URLs to attempt
    if (window.location.protocol === 'https:') {
        // If served over HTTPS, WS will be blocked by mixed content policy, so only try WSS
        connectionAttempts = [`wss://${host}:${port}`];
    } else {
        // If local/HTTP, try WSS first, then fallback to WS
        connectionAttempts = [`wss://${host}:${port}`, `ws://${host}:${port}`];
    }

    connectionIndex = 0;
    btnConnect.disabled = true;
    statusDiv.textContent = "Connecting...";

    attemptConnection();
}

function attemptConnection() {
    if (connectionIndex >= connectionAttempts.length) {
        log(`All connection attempts failed.`, "error");
        btnConnect.disabled = false;
        statusDiv.textContent = "Disconnected";
        return;
    }

    const url = connectionAttempts[connectionIndex];
    log(`Connecting to ${url}...`);

    try {
        socket = new WebSocket(url);

        socket.onopen = () => {
            log(`WebSocket Open on ${url}. Sending Handshake...`);
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
            if (!isConnected) {
                log(`Connection to ${url} closed/failed.`);
                connectionIndex++;
                attemptConnection();
            } else {
                log("Disconnected.");
                isConnected = false;
                statusDiv.textContent = "Disconnected";
                statusDiv.classList.replace("connected", "disconnected");
                btnConnect.textContent = "Connect";
                btnConnect.disabled = false;
                enablePanels(false);
                connectionInfo.textContent = "";
                socket = null;
            }
        };

        socket.onerror = (err) => {
            if (!isConnected) {
                log(`WebSocket Error on ${url}`, "warn");
            } else {
                log("WebSocket Error", "error");
                console.error(err);
            }
        };

    } catch (e) {
        log(`Connection failed for ${url}: ${e.message}`, "error");
        if (!isConnected) {
            connectionIndex++;
            attemptConnection();
        } else {
            btnConnect.disabled = false;
        }
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
    } else if (msg.startsWith("TAUSTATE:")) {
        const state = msg.substring(9).trim();
        log(`Tau State:\n${state}`, 'success');
        if (ruleEditor && state) {
            ruleEditor.setValue(state);
        }
    } else if (msg.startsWith("SEQUENCE: ")) {
        const seq = parseInt(msg.split(":")[1].trim());
        statSequence.textContent = seq;
        // Only update pending if it's null (initial load) or the confirmed sequence has caught up/surpassed our local tracking
        if (pendingSequence === null || seq > pendingSequence) {
            pendingSequence = seq;
        }
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
    } else if (msg.startsWith("FAILURE:")) {
        log(msg, "error");
        // Reset our optimistic sequence if a transaction failed
        pendingSequence = null;
    } else if (msg.startsWith("SUCCESS:")) {
        log(msg, "success");
    }
}

function refreshKnownAccounts() {
    sendRpc("getallaccounts");
}

let lastKnownServerAccounts = [];

function updateKnownAccounts(accounts = null) {
    if (accounts !== null) lastKnownServerAccounts = accounts;

    const listEl = document.getElementById('known-accounts-menu');
    if (!listEl) {
        log("Error: could not find known accounts menu element.", "error");
        return;
    }

    listEl.innerHTML = '<li><h6 class="dropdown-header">Contacts & Known Accounts</h6></li>'; // Clear

    // 1. Add Contacts from Address Book 
    const contactKeys = Object.keys(addressBook).sort();
    if (contactKeys.length > 0) {
        contactKeys.forEach(name => {
            const pubkey = addressBook[name];
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.className = 'dropdown-item';
            a.style.fontFamily = 'monospace';
            a.href = '#';
            a.textContent = `👤 ${name} (${pubkey.substring(0, 12)}...)`;
            a.title = pubkey;
            a.addEventListener('click', (e) => {
                e.preventDefault();
                txRecipient.value = pubkey;
            });
            li.appendChild(a);
            listEl.appendChild(li);
        });

        listEl.appendChild(document.createElement('li')).innerHTML = '<hr class="dropdown-divider">';
    }

    if (!Array.isArray(lastKnownServerAccounts) || lastKnownServerAccounts.length === 0) return;

    lastKnownServerAccounts.forEach(acc => {
        // Skip adding it again if it's already in the users address book (exact match)
        if (Object.values(addressBook).includes(acc)) return;

        const li = document.createElement('li');
        const a = document.createElement('a');
        a.className = 'dropdown-item';
        a.style.fontFamily = 'monospace';
        a.href = '#';
        a.textContent = `🌐 ${acc}`;
        a.addEventListener('click', (e) => {
            e.preventDefault();
            txRecipient.value = acc;
        });
        li.appendChild(a);
        listEl.appendChild(a);
    });
    log(`Refreshed ${lastKnownServerAccounts.length} known accounts.`);
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

    // Reset pending sequence when switching wallets
    pendingSequence = null;

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
    const ruleInputPreCheck = ruleEditor ? ruleEditor.getValue().trim() : txRule.value.trim();

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
    // Get sequence: Use pendingSequence if available, otherwise fallback to UI stat.
    let seq = pendingSequence !== null ? pendingSequence : parseInt(statSequence.textContent);

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
    const amountNum = amountVal === "" ? NaN : Number(amountVal);
    const shouldSendTransfer = recipient && amountVal && (amountNum !== 0 || !ruleInputPreCheck);

    if (shouldSendTransfer) {
        if (!Number.isFinite(amountNum) || !Number.isInteger(amountNum)) {
            log("Amount must be an integer.", "error");
            return;
        }
        if (amountNum < 0 || amountNum > MAX_TAU_TRANSFER_AMOUNT) {
            log(`Amount must be between 0 and ${MAX_TAU_TRANSFER_AMOUNT}.`, "error");
            return;
        }
        // "1" is transfer: [[from, to, amount]]
        ops["1"] = [[senderPub, recipient, amountVal.toString()]];
    }

    // 2. Rule Logic
    if (ruleInputPreCheck) {
        if (!validateRuleSyntax(ruleInputPreCheck)) {
            log("Invalid Rule Syntax. Correct it before sending.", "error");
            return;
        }
        // Allow comments in the UI, but strip them before sending to the node.
        // This is IMPORTANT because the current code joins lines with spaces,
        // and a '#' would comment out everything after it on the same line.
        const noComments = stripTauComments(ruleInputPreCheck);
        ops["0"] = noComments.split('\n').map(l => l.trim()).filter(Boolean).join(' ');
    }

    // 3. Custom Ops Logic
    const customInput = customEditor ? customEditor.getValue().trim() : txCustom.value.trim();
    if (customInput) {
        const lines = customInput.split('\n');
        for (let line of lines) {
            line = line.trim();
            if (!line) continue;

            const parts = line.split(':');
            if (parts.length < 2) {
                log(`Invalid custom op format: "${line}". Use Key:Value`, "error");
                return;
            }
            const keyStr = parts[0].trim();
            // Re-join the rest in case value contained colons
            const valStr = parts.slice(1).join(':').trim();

            const kInt = parseInt(keyStr);
            if (isNaN(kInt)) {
                log(`Custom key must be an integer: "${keyStr}"`, "error");
                return;
            }
            if (kInt < 4) {
                log(`Custom key must be >= 4 (reserved): "${keyStr}"`, "error");
                return;
            }
            ops[keyStr] = valStr;
        }
    }

    if (Object.keys(ops).length === 0) {
        log("Nothing to send. Specify recipient+amount OR a rule.", "error");
        return;
    }

    // --- Build Confirmation Summary ---
    let summaryText = `Please confirm your transaction:\n\n`;

    if (shouldSendTransfer) {
        // Try to find recipient name from address book if saved
        const recName = Object.keys(addressBook).find(name => addressBook[name] === recipient);
        summaryText += `🔹 Transfer:\n  Amount: ${amountVal}\n  To: ${recName ? `${recName} (${recipient.substring(0, 16)}...)` : recipient.substring(0, 24) + '...'}\n\n`;
    }

    if (ruleInputPreCheck) {
        summaryText += `📜 Rule attached:\n  ${ops["0"]}\n\n`;
    }

    if (customInput) {
        let count = 0;
        let customOpsText = '';
        for (const [k, v] of Object.entries(ops)) {
            // Skip rule (0) and transfer ops (1-4 if transfer is sent)
            if (k === "0") continue;
            if (shouldSendTransfer && ["1", "2", "3", "4"].includes(k)) continue;
            count++;
            customOpsText += `  ${k}: ${v}\n`;
        }
        summaryText += `⚙️ Custom Operations: ${count} defined.\n${customOpsText}\n`;
    }

    summaryText += `Sign and send this to the network?`;

    if (!await customConfirm(summaryText)) {
        log("Transaction cancelled by user.", "warn");
        return;
    }

    // Payload for the wire (what gets sent to the server)
    const payload = {
        "tx_type": "user_tx",
        "sender_pubkey": senderPub,
        "sequence_number": seq,
        "expiration_time": Math.floor(Date.now() / 1000) + 300, // 5 mins
        "operations": ops,
        "fee_limit": "0"
    };

    try {
        // Build signing dict that mirrors server-side _get_signing_message_bytes exactly.
        // For user_tx the server constructs:
        //   {sender_pubkey, sequence_number, expiration_time, fee_limit, tx_type, operations}
        // Canonicalized with sorted keys, no whitespace separators.
        const signingDict = {
            "sender_pubkey": payload.sender_pubkey,
            "sequence_number": payload.sequence_number,
            "expiration_time": payload.expiration_time,
            "fee_limit": payload.fee_limit,
            "tx_type": "user_tx",
            "operations": payload.operations
        };

        const canonicalJson = canonicalize(signingDict);
        const msgBytes = new TextEncoder().encode(canonicalJson);
        const msgHash = sha256(msgBytes);
        const sig = bls.sign(msgHash, currentKeyPair.priv);

        const fullTx = {
            ...payload,
            "signature": bytesToHex(sig)
        };

        const cmd = "sendtx " + JSON.stringify(fullTx);
        sendRpc(cmd);
        log("Transaction sent.", "sent");

        // Optimistically increment sequence for subsequent rapid sends
        pendingSequence = seq + 1;

        // Auto-clear inputs
        txRecipient.value = '';
        txAmount.value = '';
        if (ruleEditor) ruleEditor.setValue('');
        if (customEditor) customEditor.setValue('');

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

// Strip Tau comments while preserving #b and #x literals.
function stripTauComments(ruleText) {
    if (!ruleText) return "";
    return ruleText.split('\n').map(line => {
        let out = "";
        for (let i = 0; i < line.length; i++) {
            if (line[i] === '#') {
                const next = i + 1 < line.length ? line[i + 1].toLowerCase() : '';
                if (next === 'b' || next === 'x') {
                    out += '#';
                } else {
                    break; // Start of a real comment
                }
            } else {
                out += line[i];
            }
        }
        return out;
    }).join('\n');
}

function validateRuleSyntax(rule) {
    if (!rule || !rule.trim()) {
        ruleValidationStatus.textContent = "";
        return true;
    }
    const errors = [];
    // Validate the semantic rule text, not comments.
    const withoutComments = stripTauComments(rule);
    const trimmed = withoutComments.trim();

    // 1. Check: Must end with '.'
    if (!trimmed.endsWith('.')) {
        errors.push("Rule must end with a period '.'.");
    }

    // 2. Check brackets
    const stack = [];
    const pairs = { ')': '(', ']': '[', '}': '{' };
    for (let char of withoutComments) {
        if (['(', '[', '{'].includes(char)) {
            stack.push(char);
        } else if ([')', ']', '}'].includes(char)) {
            if (stack.length === 0 || stack.pop() !== pairs[char]) {
                errors.push(`Mismatched closing bracket '${char}'.`);
            }
        }
    }
    if (stack.length > 0) errors.push(`Unclosed brackets: ${stack.join(', ')}.`);

    // 3. Check invalid chars
    const allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_[]()='&|!<>+-*/%^: \t\n\r{}#?,.";
    for (let char of withoutComments) {
        if (!allowedChars.includes(char)) {
            errors.push(`Invalid character '${char}'.`);
        }
    }

    // 4. Basic operator checks
    const tokens = trimmed.split(/\s+/).filter(t => t);
    const operators = new Set(["&&", "||", "&", "|", "=", "->", "<-", "<->"]);
    if (tokens.length > 0) {
        if (operators.has(tokens[0])) errors.push(`Rule cannot start with operator: '${tokens[0]}'.`);
        if (operators.has(tokens[tokens.length - 1])) errors.push(`Rule cannot end with operator: '${tokens[tokens.length - 1]}'.`);
    }

    // 5. Check for consecutive operands (garbage words)
    // Identify words/identifiers and check if two appear without an operator between them (unless first is keyword).
    const keywords = new Set(["always", "eventually", "next", "future", "tau", "forall", "exists", "release", "until", "ex"]);
    const reWord = /[a-zA-Z0-9_#]+/g;
    let match;
    const words = [];
    while ((match = reWord.exec(withoutComments)) !== null) {
        words.push({ text: match[0], index: match.index, end: match.index + match[0].length });
    }

    for (let i = 0; i < words.length - 1; i++) {
        const curr = words[i];
        const next = words[i + 1];

        // Check text between them
        const substring = withoutComments.slice(curr.end, next.index);

        // If there is ONLY whitespace between two identifiers, it's suspicious unless one of them is a keyword.
        if (!substring.trim()) {
            if (!keywords.has(curr.text) && !keywords.has(next.text)) {
                errors.push(`Unexpected sequence: '${curr.text} ${next.text}'. Missing operator?`);
                break; // One error is enough
            }
        }
    }

    // 6. Heuristic for meaningful content (Backup check)
    if (errors.length === 0) {
        const hasOperator = ['=', ':=', '->', '<-', '<->'].some(op => withoutComments.includes(op));
        const firstWord = tokens[0] ? tokens[0].split(/[^\w]/)[0] : "";
        const startsWithKeyword = keywords.has(firstWord);
        if (!hasOperator && !startsWithKeyword) {
            errors.push("Rule must contain an assignment/operator or start with a keyword (always, tau, etc).");
        }
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
    const RESERVED_MAX_IDX = 5;

    const randOut = () => (RESERVED_MAX_IDX + 1) + Math.floor(Math.random() * 10); // o6..o15
    const randIn = () => 1 + Math.floor(Math.random() * 4); // i1..i4
    const outA = randOut();
    const outB = randOut();
    const inA = randIn();
    const inB = randIn();
    const inC = randIn();
    const sh1 = 1 + Math.floor(Math.random() * 7);
    const sh2 = 1 + Math.floor(Math.random() * 7);
    const bit = Math.floor(Math.random() * 2);

    const hx = (n) => `{ #x${n.toString(16).padStart(2, '0')} }:bv[16]`;

    const templates = [
        () => [
            `# Example 1 - Constant flag output (sanity test)`,
            `# Writes a stable 0/1 into an unused output stream every step.`,
            `always (o${outA}[t] = ${hx(bit)}).`
        ].join('\n'),

        () => [
            `# Example 2 - Threshold gate (classifier-like)`,
            `# If i${inA}+i${inB} >= 0x80 then output 1 else 0 (bv[16]).`,
            `always ( ((i${inA}[t]:bv[16] + i${inB}[t]:bv[16]) >= ${hx(0x80)} && o${outA}[t] = ${hx(1)}) || ((i${inA}[t]:bv[16] + i${inB}[t]:bv[16]) < ${hx(0x80)} && o${outA}[t] = ${hx(0)}) ).`
        ].join('\n'),

        () => [
            `# Example 3 - Feature extraction (bit shifts + combine)`,
            `# Produces an 8-bit feature deterministically from two inputs.`,
            `always ( o${outA}[t]:bv[16] = (i${inA}[t]:bv[16] >> ${hx(sh1)}) + (i${inB}[t]:bv[16] << ${hx(sh2)}) ).`
        ].join('\n'),

        () => [
            `# Example 4 - Temporal check`,
            `# If i${inA} increased vs previous step, set a flag (bv[16]).`,
            `always ( ((i${inA}[t]:bv[16] > i${inA}[t-1]:bv[16]) && o${outA}[t] = ${hx(1)}) || ((i${inA}[t]:bv[16] <= i${inA}[t-1]:bv[16]) && o${outA}[t] = ${hx(0)}) ).`
        ].join('\n'),

        () => [
            `# Example 5 - Multiple outputs`,
            `# Two deterministic arithmetic relations in one rule.`,
            `always ( (o${outA}[t]:bv[16] = i${inA}[t]:bv[16] + i${inB}[t]:bv[16]) && (o${outB}[t]:bv[16] = i${inC}[t]:bv[16] - i${inB}[t]:bv[16]) ).`
        ].join('\n'),

        () => [
            `# Example 6 - "Network" style rule with local variables`,
            `# Computes two hidden gates and outputs:`,
            `# - o${outA}[t] allow flag (bv[16])`,
            `# - o${outB}[t] risk-ish score (bv[16])`,
            `always ( ex s1 ex s2 ex h1 ex h2 (`,
            `  (s1 = (i${inA}[t]:bv[16] * ${hx(0x03)}) + (i${inB}[t]:bv[16] * ${hx(0x02)}))`,
            `  && ((s1 >= ${hx(0x80)} && h1 = ${hx(1)}) || (s1 < ${hx(0x80)} && h1 = ${hx(0)}))`,
            `  && (s2 = (i${inC}[t]:bv[16] * ${hx(0x05)}) + (${hx(0x00)} - i${inA}[t]:bv[16]))`,
            `  && ((s2 >= ${hx(0x40)} && h2 = ${hx(1)}) || (s2 < ${hx(0x40)} && h2 = ${hx(0)}))`,
            `  && (o${outB}[t]:bv[16] = (h2:bv[16] * ${hx(0xC8)}) + ((${hx(0x01)} - h1:bv[16]) * ${hx(0x32)}))`,
            `  && ( (h2 = ${hx(0)} && o${outA}[t] = ${hx(1)}) || (h2 = ${hx(1)} && o${outA}[t] = ${hx(0)}) )`,
            `) ).`
        ].join('\n'),
    ];

    return templates[Math.floor(Math.random() * templates.length)]();
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

async function saveCurrentWallet() {
    if (!currentKeyPair) {
        log("No wallet to save.", "error");
        return;
    }
    const name = walletNameInput.value.trim();
    if (!name) {
        log("Please enter a wallet name.", "error");
        return;
    }

    if (savedWallets[name]) {
        if (!await customConfirm(`Overwrite wallet "${name}"?`)) return;
    }

    const pubhex = bytesToHex(currentKeyPair.pub);
    const existingName = Object.keys(savedWallets).find(k => savedWallets[k].pub === pubhex && k !== name);
    if (existingName) {
        if (!await customConfirm(`Warning: This wallet is already saved as "${existingName}". Save it again as "${name}"?`)) {
            return;
        }
    }

    savedWallets[name] = {
        priv: bytesToHex(currentKeyPair.priv),
        pub: pubhex
    };

    localStorage.setItem('tau_saved_wallets', JSON.stringify(savedWallets));

    updateWalletList();
    walletSelect.value = name; // Select it
    btnDeleteWallet.disabled = false;

    walletNameInput.value = "";
    saveWalletArea.style.display = "none";
    log(`Wallet "${name}" saved.`);
}

async function deleteSelectedWallet() {
    const name = walletSelect.value;
    if (!name || !savedWallets[name]) return;

    if (await customConfirm(`Delete wallet "${name}"?`)) {
        delete savedWallets[name];
        localStorage.setItem('tau_saved_wallets', JSON.stringify(savedWallets));
        updateWalletList();
        walletSelect.value = "";
        btnDeleteWallet.disabled = true;
        log(`Wallet "${name}" deleted.`);
    }
}

// --- Address Book Functions ---

function loadAddressBook() {
    try {
        const stored = localStorage.getItem('tau_address_book');
        if (stored) {
            addressBook = JSON.parse(stored);
        }
    } catch (e) {
        console.error("Failed to load address book", e);
    }
    renderAddressBook();
}

async function saveContact() {
    const name = contactNameInput.value.trim();
    const pubkey = contactPubkeyInput.value.trim();

    if (!name || !pubkey) {
        log("Contact name and public key are required.", "error");
        return;
    }

    // Quick hex validation
    if (!/^[0-9a-fA-F]+$/.test(pubkey) || pubkey.length < 64) {
        log("Public key must be a valid hex string of at least 64 chars.", "error");
        return;
    }

    if (addressBook[name]) {
        if (!await customConfirm(`Overwrite contact "${name}"?`)) return;
    }

    // Check for duplicate pubkey under a different name
    const existingName = Object.keys(addressBook).find(k => addressBook[k] === pubkey && k !== name);
    if (existingName) {
        if (!await customConfirm(`Warning: This public key is already saved as "${existingName}". Save it again as "${name}"?`)) {
            return;
        }
    }

    addressBook[name] = pubkey;
    localStorage.setItem('tau_address_book', JSON.stringify(addressBook));

    contactNameInput.value = "";
    contactPubkeyInput.value = "";
    log(`Contact "${name}" saved.`);

    renderAddressBook();
}

async function deleteContact(name) {
    if (await customConfirm(`Delete contact "${name}"?`)) {
        delete addressBook[name];
        localStorage.setItem('tau_address_book', JSON.stringify(addressBook));
        log(`Contact "${name}" deleted.`);
        renderAddressBook();
    }
}

function renderAddressBook() {
    contactsListDiv.innerHTML = '';
    const keys = Object.keys(addressBook);

    if (keys.length === 0) {
        contactsListDiv.innerHTML = '<p style="color: #aaa; margin: 0; font-style: italic;">No contacts saved.</p>';
        return;
    }

    keys.sort().forEach(name => {
        const pubkey = addressBook[name];

        const item = document.createElement('div');
        item.style.display = 'flex';
        item.style.justifyContent = 'space-between';
        item.style.alignItems = 'center';
        item.style.borderBottom = '1px solid #444';
        item.style.padding = '8px 4px';

        const info = document.createElement('div');
        info.style.overflow = 'hidden';
        info.style.textOverflow = 'ellipsis';
        info.style.whiteSpace = 'nowrap';
        info.style.marginRight = '10px';
        info.innerHTML = `<strong>${name}</strong> <span style="color:#888; font-size: 0.85em; margin-left:10px;" title="${pubkey}">${pubkey.substring(0, 16)}...</span>`;

        const actions = document.createElement('div');

        const btnFill = document.createElement('button');
        btnFill.className = 'btn-sm btn-outline-primary';
        btnFill.style.marginRight = '5px';
        btnFill.textContent = 'Use';
        btnFill.title = 'Fill in Recipient field';
        btnFill.onclick = () => {
            txRecipient.value = pubkey;
            // Scroll to TX panel assuming they want to send now
            document.getElementById('tx-panel').scrollIntoView({ behavior: 'smooth' });
            log(`Recipient set to ${name}.`);
        };

        const btnDel = document.createElement('button');
        btnDel.className = 'btn-sm danger-btn';
        btnDel.textContent = 'Del';
        btnDel.onclick = () => deleteContact(name);

        actions.appendChild(btnFill);
        actions.appendChild(btnDel);

        item.appendChild(info);
        item.appendChild(actions);
        contactsListDiv.appendChild(item);
    });

    // Update the dropdown any time the address book is re-rendered
    updateKnownAccounts();
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

// --- Rule Templates ---
const ruleTemplates = {
    "Block all transfers": `# ---------------------------------------------------------
# BLOCK ALL TRANSFERS FROM MY ACCOUNT
# ---------------------------------------------------------
# This rule unconditionally blocks all outgoing transfers from 
# your specific account. Because Tau rules become part of the 
# global state, we must scope this rule strictly to your own 
# public key (i3) so we don't accidentally block the entire network!
#
# i3[t] : The sender's public key (represented as a 384-bit vector)
# o5[t] : Output signal (0 = block, 1 = allow)
# ---------------------------------------------------------
# Replace '#x1111...1111' with your own 96-character public key hex.
always (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] -> o5[t] = {0}:bv[16]).`,

    "Limit transfers to max 5000": `# ---------------------------------------------------------
# LIMIT TRANSFERS FROM MY ACCOUNT TO MAX 5000
# ---------------------------------------------------------
# This rule ensures that any outgoing transfer from this account
# cannot exceed a maximum value of 5000. It is scoped to your
# public key, so it only restricts your own transactions globally.
#
# i1[t] : The amount being transferred in the current transaction.
# i3[t] : The sender's public key (represented as a 384-bit vector)
# o5[t] : Output signal (0 = block if limit exceeded)
# ---------------------------------------------------------
# Replace '#x1111...1111' with your own 96-character public key hex.
always ((i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] && i1[t] > {5000}:bv[64]) -> o5[t] = {0}:bv[16]).`,

    "Only allow transfers to a specific address": `# ---------------------------------------------------------
# WHITELIST SPECIFIC RECIPIENT FOR MY ACCOUNT
# ---------------------------------------------------------
# This rule restricts outgoing transfers from your account so they 
# can only be sent to one specific, verified address. Any attempt 
# to send funds to a different address will be blocked.
#
# i3[t] : The sender's public key
# i4[t] : The recipient's public key
# o5[t] : Output signal (0 = block, 1 = allow)
# ---------------------------------------------------------
# Replace the placeholders with your public key and the allowed recipient's key.
always ((i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] && !(i4[t] = {#x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222}:bv[384])) ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]).`,

    "Require a specific custom input": `# ---------------------------------------------------------
# REQUIRE TWO-FACTOR / CUSTOM DATA
# ---------------------------------------------------------
# This rule requires a specific custom data payload to be attached 
# to any transaction originating from your account. This acts like 
# a secret password that must be present.
#
# i3[t] : The sender's public key
# i6[t] : The custom input data provided in the transaction
#         (In this example, we expect #x4142 which is 'AB')
# o5[t] : Output signal (0 = block, 1 = allow)
# ---------------------------------------------------------
always ((i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] && !(i6[t] = {#x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004142}:bv[384])) ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]).`,

    "Time-locked (Block transfers before time X)": `# ---------------------------------------------------------
# TIME-LOCKED WALLET
# ---------------------------------------------------------
# This rule creates a time-lock, preventing any funds from being
# transferred out of your wallet until a specific block timestamp
# has been reached in the future.
#
# i3[t] : The sender's public key
# i5[t] : The current block timestamp (Unix epoch format, injected as integer)
# o5[t] : Output signal (0 = block, 1 = allow)
# ---------------------------------------------------------
# Note: 1700000000 is an example Unix timestamp.
always ((i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] && i5[t] < {1700000000}:bv[64]) ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]).`,

    "Time-Decaying Multi-Signature Vault": `# ---------------------------------------------------------
# TIME-DECAYING MULTI-SIGNATURE VAULT
# ---------------------------------------------------------
# This sophisticated contract requires a Co-Signer to approve
# transactions, but ONLY before a specific expiration timestamp.
# After the timestamp passes, the primary wallet owner regains
# full independent control of the funds.
#
# Useful for temporal escrows, trust funds, or security setups
# where you want backup control to expire after a certain date.
#
# i3[t] : The primary sender's public key (The Vault)
# i5[t] : The current block timestamp (injected as integer)
# i6[t] : Custom input payload containing the Co-Signer's public key
# o5[t] : Output signal (0 = block, 1 = allow)
# ---------------------------------------------------------
always (
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] 
   && i5[t] < {1800000000}:bv[64] 
   && !(i6[t] = {#x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222}:bv[384])) 
  ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]
).`,

    "Temporary Spending Limit": `# ---------------------------------------------------------
# TEMPORARY SPENDING LIMIT STRATEGY
# ---------------------------------------------------------
# This rule enforces different transfer ceilings based on the
# current time. Before the designated timestamp, the account
# has a high spending limit (e.g., 5,000). After the timestamp 
# expires, the spending limit permanently drops to a lower
# threshold (e.g., 500).
#
# i1[t] : The amount being transferred
# i3[t] : The sender's public key
# i5[t] : The current block timestamp (injected as integer)
# o5[t] : Output signal (0 = block transaction, 1 = allow)
# ---------------------------------------------------------
always (
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384]) ->
  (
    # Phase 1: High Limit before Timestamp (1800000000)
    (i5[t] < {1800000000}:bv[64] && i1[t] > {5000}:bv[64] ? o5[t] = {0}:bv[16] : 
      # Phase 2: Low Limit after Timestamp (1800000000)
      (!(i5[t] < {1800000000}:bv[64]) && i1[t] > {500}:bv[64] ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]))
  )
).`,

    "Escrow Contract": `# ---------------------------------------------------------
# ESCROW CONTRACT (3rd PARTY ARBITER)
# ---------------------------------------------------------
# This rule implements an Escrow mechanism on a specific account. 
# Funds from the Escrow Account remain locked (o5 = 0) unless a 
# designated 3rd-party Arbiter approves the release.
#
# Input Streams:
# i3[t] : Sender address of the transaction. We use this to scope the
#         rule globally so it ONLY affects the Escrow Account.
# i6[t] : Custom input payload containing the Arbiter's approval signal.
#         (In this example, the Arbiter must provide {#x01}:bv[8] to release)
#
# Output Stream:
# o5[t] : Output signal (0 = Keep funds locked, 1 = Release).
# ---------------------------------------------------------
# Replace '#x1111...1111' with the Escrow's public key (96-char hex).
always (
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] && !(i6[t] = {1}:bv[64])) 
  ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]
).`,

    "2FA for High Value Transfers": `# ---------------------------------------------------------
# 2FA FOR HIGH VALUE TRANSFERS (Bank Security Model)
# ---------------------------------------------------------
# This rule mimics a real-world bank account security feature.
# It is extremely clear to non-technical users:
# 
# Small, everyday transfers (up to 1,000 coins) process normally.
# However, any transfer strictly greater than 1,000 coins REQUIRES
# a 2-Factor Authentication (2FA) token to be included in the
# transaction's Custom Operations.
#
# NOTE ON SECURITY: In a production environment, this constant 
# would be a cryptographic hash (e.g., SHA-256), and the user
# would provide the pre-image. For this readable community demo, 
# we use a simple numeric token '9999'.
#
# i1[t] : The amount being transferred in the transaction.
# i3[t] : The sender's public key (384-bit BLS signature).
# i6[t] : The 2FA token provided in Custom operations. 
# o5[t] : Output signal (0 = blocks the transaction, 1 = allows).
# ---------------------------------------------------------
# Replace '#x11111111...1111' with your 96-character public key hex.
always (
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384] 
   && i1[t] > {1000}:bv[64] 
   && !(i6[t] = {9999}:bv[64])) 
  ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]
).`,

    "Multi-Signature Smart Vault": `# ---------------------------------------------------------
# MULTI-SIGNATURE SMART VAULT
# ---------------------------------------------------------
# This contract uses mathematical logic and bitvector 
# arithmetic to manage fund security without relying on hidden states.
#
# STREAMS:
# i1[t]   : Current transfer amount
# i3[t]   : Primary sender's public key (The Vault)
# i4[t]   : Secondary/Co-signer public key (Authenticated by network)
# o5[t]   : Output signal (0 = block transaction, 1 = allow)
# ---------------------------------------------------------

always (
  # SCOPE: This rule only triggers when the Vault is the sender.
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384]) 
  -> 
  (
    # 1. MULTI-SIGNATURE FOR LARGE TRANSFERS
    # If the amount is > 1000, the specified Co-Signer public key MUST be present in Custom operation '4'.
    ( (i1[t] > {1000}:bv[64] && !(i4[t] = {#x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222}:bv[384])) 
      ? o5[t] = {0}:bv[16] :
      
      # 2. ABSOLUTE CEILING
      # Even with a co-signer, no single normal transfer can exceed 10,000.
      ( (i1[t] > {10000}:bv[64]) ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16] )
    )
).`,

    "Adaptive Treasury Vault (Pointwise Revision Demo)": `# =============================================================
# ADAPTIVE TREASURY VAULT — Layered Policy with Pointwise Revision
# =============================================================
#
# ARCHITECTURE:
#   Both layers write to the SAME policy output stream o5.
#   Tau logically composes multiple always(...) clauses via &&,
#   so a transfer is allowed ONLY if ALL clauses output o5 = 1.
#
#   Layer 1 — Immutable hard safety controls (time-lock, abs cap,
#             approved counterparty). Cannot be revised.
#   Layer 2 — Revisable per-transfer spending cap.
#             Pointwise revision replaces ONLY this clause.
#
# ENGINE ENFORCEMENT:
#   The engine reads o5 after each transfer validation step:
#     o5 = 0       → block   (user policy rejects transfer)
#     o5 = 1       → allow   (user policy approves transfer)
#     o5 absent    → allow   (no user policy triggered)
#
# SCOPE:
#   This contract only constrains the treasury account (i3 match).
#   All other senders pass through (vacuous truth from '->').
#
# STREAM TYPES:
#   i1[t] : transfer amount           (bv[16])
#   i3[t] : sender public key         (bv[384])
#   i4[t] : recipient/counterparty    (bv[384])
#   i5[t] : block timestamp           (bv[16])
#   o5[t] : policy guard signal       (bv[16]: 0=block, 1=allow)
#
# ----- POINTWISE REVISION INSTRUCTIONS -----
# To revise ONLY the spending cap (Layer 2), send a SEPARATE
# transaction with a new rule that redefines the spending cap
# clause on o5. Layer 1 remains untouched because Tau's
# pointwise revision targets the specific clause being replaced.
#
# REVISION EXAMPLE A — Raise cap to 10000:
#   always (
#     (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384]
#       && i1[t] > {10000}:bv[16])
#     ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]
#   ).
#
# REVISION EXAMPLE B — Time-dependent cap using 'ex':
#   always (
#     ex c (
#       (i5[t] >= {1800000000}:bv[16] && c = {20000}:bv[16])
#       || (i5[t] < {1800000000}:bv[16] && c = {10000}:bv[16])
#     ) && (
#       (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384]
#         && i1[t] > c:bv[16])
#       ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]
#     )
#   ).
# =============================================================

# --- LAYER 1: IMMUTABLE CORE GUARD (o5) ---
(always (
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384])
  -> (
    # 1. TIME-LOCK: Block all transfers before this timestamp.
    (i5[t] < {1750000000}:bv[16]
      ? o5[t] = {0}:bv[16]
      : (
        # 2. ABSOLUTE CAP: No single transfer may exceed 50000.
        (i1[t] > {50000}:bv[16]
          ? o5[t] = {0}:bv[16]
          : (
            # 3. APPROVED-COUNTERPARTY: Transfers above 1000 require
            #    the recipient to be a specific approved counterparty.
            (i1[t] > {1000}:bv[16]
              && !(i4[t] = {#x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222}:bv[384]))
            ? o5[t] = {0}:bv[16]
            : o5[t] = {1}:bv[16]
          ))
      ))
  )
)) &&
# --- LAYER 2: REVISABLE PER-TRANSFER SPENDING CAP (o5) ---
# This clause is the TARGET for pointwise revision.
# Tau composes it with Layer 1: transfer allowed only if
# BOTH clauses output o5 = 1.
(always (
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384]
    && i1[t] > {5000}:bv[16])
  ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]
)).`,

    "Programmable Finance Protocol (Aspirational Features)": `# ================================================================
# PROGRAMMABLE FINANCE PROTOCOL — Forward-Looking Tau Contract
# ================================================================
#
# PURPOSE:
#   This contract demonstrates features that the Tau language NEEDS
#   to support for real-world blockchain finance. Each section is
#   annotated with its implementation status:
#
#     [AVAILABLE]    — works in Tau v0.7-alpha today
#     [ASPIRATIONAL] — requires language extensions
#
# This serves as a development roadmap for Tau language features
# needed to make on-chain programmable finance practical.
#
# ================================================================
# STREAM LAYOUT:
#   INPUTS:
#     i1[t] : transfer amount         (bv[16])
#     i3[t] : sender address           (bv[384])
#     i4[t] : recipient address        (bv[384])
#     i5[t] : block timestamp          (bv[16])
#     i6[t] : operation type           (bv[16])
#             0=transfer, 1=governance_vote, 2=vesting_claim
#     i7[t] : governance proposal id   (bv[16])
#     i8[t] : vote weight / approval   (bv[16])
#
#   OUTPUTS:
#     o5[t] : policy decision          (bv[16]: 0=block, 1=allow)
#     o7[t] : governance tally         (bv[16]: accumulated votes)
#     o8[t] : vesting release amount   (bv[16]: claimable tokens)
#     o9[t] : audit log / reason code  (bv[16])
#             0=ok, 1=rate_limit, 2=governance_denied,
#             3=vesting_locked, 4=fee_too_low
# ================================================================


# ================================================================
# SECTION 1: BASIC SENDER-SCOPED TRANSFER GUARD
# [AVAILABLE] — standard sender match + amount cap
# ================================================================
# This part works today. It guards the treasury address with
# a hard spending cap and time-lock.

(always (
  (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384])
  -> (
    (i1[t] > {50000}:bv[16]
      ? o5[t] = {0}:bv[16]
      : o5[t] = {1}:bv[16])
  )
))


# ================================================================
# SECTION 2: TEMPORAL RATE LIMITING (Sliding Window)
# [ASPIRATIONAL] — requires: o5[t-1] temporal back-references
#                             on OUTPUT streams, and bv addition
#                             across time steps
# ================================================================
# GOAL: Block transfers if total spending in the last N steps
#       exceeds a threshold. This requires:
#   1. Referencing past OUTPUT values (o[t-1], o[t-2], ...)
#   2. Accumulating sums across a time window
#   3. Comparing accumulated totals against a budget
#
# PSEUDOCODE (not valid Tau today):
#
#   # Track cumulative spending in a rolling window
#   # spent_window[t] accumulates the last 10 transfers
#   spent_window[0](amt) := amt
#   spent_window[n](amt) := spent_window[n-1](amt) + i1[t-n]
#
#   always (
#     i3[t] = TREASURY
#     -> ex total (
#       total = spent_window[10](i1[t])
#       && (total > {100000}:bv[16]
#         ? (o5[t] = {0}:bv[16] && o9[t] = {1}:bv[16])
#         : o5[t] = {1}:bv[16])
#     )
#   ).
#
# WHY THIS MATTERS:
#   Rate limiting is the #1 requested DeFi safety feature.
#   Without temporal accumulation, contracts cannot express
#   "no more than X tokens per day" — a basic requirement
#   for treasury management, anti-whale, and compliance.
#
# REQUIRED TAU EXTENSIONS:
#   - Output stream temporal back-references: o5[t-1]
#   - Bitvector addition across time-indexed terms
#   - Recurrence relations over stream values (not just variables)


# ================================================================
# SECTION 3: DYNAMIC FEE CALCULATION
# [ASPIRATIONAL] — requires: bv multiplication, division,
#                             percentage arithmetic
# ================================================================
# GOAL: Compute a fee as a percentage of transfer amount and
#       reject transfers that don't include sufficient fee.
#
# PSEUDOCODE:
#
#   # Fee = 0.5% of amount = amount * 5 / 1000
#   # Requires: bv multiplication and division operators
#   always (
#     i6[t] = {0}:bv[16]    # operation type = transfer
#     -> ex fee (
#       fee = (i1[t] * {5}:bv[16]) / {1000}:bv[16]
#       && (i9[t] < fee      # i9 = fee provided by sender
#         ? (o5[t] = {0}:bv[16] && o9[t] = {4}:bv[16])
#         : o5[t] = {1}:bv[16])
#     )
#   ).
#
# WHY THIS MATTERS:
#   Every blockchain needs fee models. Percentage-based fees,
#   tiered pricing, and dynamic fee markets all require
#   multiplication and division — operations that bitvector
#   theory supports but Tau doesn't expose yet.
#
# REQUIRED TAU EXTENSIONS:
#   - Bitvector multiplication: a * b
#   - Bitvector division: a / b
#   - Bitvector modulo: a % b (useful for remainder checks)


# ================================================================
# SECTION 4: MULTI-PARTY GOVERNANCE (Weighted Voting)
# [ASPIRATIONAL] — requires: persistent state, aggregate
#                             functions, cross-step accumulation
# ================================================================
# GOAL: Allow a set of governance addresses to vote on proposals.
#       A proposal passes when accumulated vote weight exceeds
#       a threshold. The transfer is allowed only if the relevant
#       proposal has passed.
#
# PSEUDOCODE:
#
#   # Governance predicate using recurrence for vote tally
#   # Each step where i6=1 (vote), accumulate weight from i8
#   tally[0](proposal) := {0}:bv[16]
#   tally[n](proposal) := (
#     (i6[t-n] = {1}:bv[16] && i7[t-n] = proposal)
#     ? tally[n-1](proposal) + i8[t-n]
#     : tally[n-1](proposal)
#   )
#
#   # Governance quorum check
#   governance_approved(proposal) :=
#     ex total (
#       total = tally[100](proposal)
#       && total >= {500}:bv[16]   # quorum = 500 weight
#     )
#
#   # Large transfers (>10000) require governance approval
#   always (
#     (i3[t] = TREASURY && i1[t] > {10000}:bv[16])
#     -> (governance_approved({1}:bv[16])
#       ? o5[t] = {1}:bv[16]
#       : (o5[t] = {0}:bv[16] && o9[t] = {2}:bv[16]))
#   ).
#
# WHY THIS MATTERS:
#   DAOs, multisig wallets, and on-chain governance all need
#   the ability to tally votes and enforce quorum. This
#   requires Tau to support:
#   - Recurrence relations that reference input streams at
#     past time steps (i6[t-n], i7[t-n], i8[t-n])
#   - Addition within recurrence bodies
#   - Cross-step state that persists across execution steps
#
# REQUIRED TAU EXTENSIONS:
#   - Stream-indexed recurrence relations: f[n] referencing i[t-n]
#   - Bitvector addition in recurrence bodies
#   - Persistent state semantics (values that survive across steps)


# ================================================================
# SECTION 5: TOKEN VESTING SCHEDULE
# [ASPIRATIONAL] — requires: bv multiplication, temporal
#                             arithmetic (timestamp differences),
#                             min/max functions
# ================================================================
# GOAL: Release tokens linearly over time. A beneficiary can
#       claim tokens proportional to elapsed time since a start
#       date, up to a total grant amount.
#
# PSEUDOCODE:
#
#   # Constants
#   VESTING_START   = {1750000000}:bv[16]
#   VESTING_END     = {1800000000}:bv[16]
#   TOTAL_GRANT     = {100000}:bv[16]
#   BENEFICIARY     = {#x333...333}:bv[384]
#
#   # Linear vesting: released = total * (now - start) / (end - start)
#   # Clamped to [0, TOTAL_GRANT]
#   vested_amount(now) := ex elapsed ex duration ex released (
#     elapsed = max({0}:bv[16], now - VESTING_START)
#     && duration = VESTING_END - VESTING_START
#     && released = min(TOTAL_GRANT, (TOTAL_GRANT * elapsed) / duration)
#     && released   # return value
#   )
#
#   # On vesting claim (i6=2):
#   always (
#     (i6[t] = {2}:bv[16] && i3[t] = BENEFICIARY)
#     -> ex claimable (
#       claimable = vested_amount(i5[t])
#       && o8[t] = claimable
#       && (i1[t] > claimable
#         ? (o5[t] = {0}:bv[16] && o9[t] = {3}:bv[16])
#         : o5[t] = {1}:bv[16])
#     )
#   ).
#
# WHY THIS MATTERS:
#   Token vesting is fundamental to crypto projects — team
#   allocations, investor lockups, community grants. It requires:
#   - Timestamp subtraction and comparison
#   - Multiplication and division for proportional calculation
#   - min/max clamping functions
#   - Output streams that emit computed values (o8 = claimable)
#
# REQUIRED TAU EXTENSIONS:
#   - min(a, b), max(a, b) as built-in or definable functions
#   - Bitvector multiplication / division
#   - Subtraction that handles underflow gracefully


# ================================================================
# SECTION 6: CROSS-STREAM COMPUTED DEPENDENCY
# [ASPIRATIONAL] — requires: multiple output streams computed
#                             from shared intermediate values
# ================================================================
# GOAL: Compute an intermediate decision once and use it to
#       drive multiple output streams (policy + audit log).
#
# PSEUDOCODE:
#
#   always (
#     i3[t] = TREASURY
#     -> ex decision ex reason (
#       # Compute decision once
#       (i1[t] > {50000}:bv[16]
#         ? (decision = {0}:bv[16] && reason = {1}:bv[16])    # blocked: rate limit
#         : (i1[t] > {10000}:bv[16] && !governance_approved()
#           ? (decision = {0}:bv[16] && reason = {2}:bv[16])  # blocked: no governance
#           : (decision = {1}:bv[16] && reason = {0}:bv[16])  # allowed
#         ))
#       # Fan out to multiple outputs
#       && o5[t] = decision
#       && o9[t] = reason
#     )
#   ).
#
# WHY THIS MATTERS:
#   Real contracts need audit trails. The ability to compute
#   a decision and simultaneously write it to a policy stream
#   AND a reason-code stream enables on-chain compliance logging.
#   Current Tau can write to multiple outputs, but computing
#   intermediate values via 'ex' and fanning them out to several
#   streams is untested at scale and may need optimization.
#
# WHAT'S NEEDED:
#   - Verification that 'ex' variables can drive multiple output
#     stream assignments within the same always(...) clause
#   - Performance optimization for multi-output resolution
#   - Engine support for reading o9 as an audit/receipt stream


# ================================================================
# SECTION 7: POINTWISE REVISION FOR GOVERNANCE UPGRADES
# [AVAILABLE] — pointwise revision works today
# ================================================================
# The governance section above can be upgraded via pointwise
# revision. For example, to change the quorum from 500 to 750:
#
#   always (
#     (i3[t] = {#x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}:bv[384]
#       && i1[t] > {10000}:bv[16])
#     -> (governance_approved_v2({1}:bv[16])
#       ? o5[t] = {1}:bv[16]
#       : (o5[t] = {0}:bv[16] && o9[t] = {2}:bv[16]))
#   ).
#
# Where governance_approved_v2 uses a threshold of 750 instead
# of 500. The old clause is replaced, new one takes effect.


# ================================================================
# SUMMARY: REQUIRED TAU LANGUAGE EXTENSIONS
# ================================================================
#
# Priority 1 (Unlocks basic DeFi):
#   - Bitvector multiplication:  a * b
#   - Bitvector division:        a / b
#   - Output temporal references: o5[t-1] in specifications
#
# Priority 2 (Unlocks governance & compliance):
#   - Stream-indexed recurrence: f[n] referencing i[t-n]
#   - Aggregate temporal functions: sum over window
#   - Cross-step persistent state semantics
#
# Priority 3 (Unlocks advanced finance):
#   - min/max built-in functions
#   - Modulo operator: a % b
#   - Multiple output stream fan-out optimization
#   - Engine support for audit/receipt streams (o9)
#
# ================================================================`
};

function initRuleTemplates() {
    const menu = document.getElementById('rule-templates-menu');
    if (!menu) return;

    for (const [name, ruleText] of Object.entries(ruleTemplates)) {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.className = 'dropdown-item';
        a.href = '#';
        a.textContent = name;
        a.addEventListener('click', (e) => {
            e.preventDefault();
            if (ruleEditor) {
                ruleEditor.setValue(ruleText);
            } else if (txRule) {
                txRule.value = ruleText;
            }
            log(`Loaded template: ${name}`);
        });
        li.appendChild(a);
        menu.appendChild(li);
    }
}

// Call this function when the window loads
window.addEventListener('load', initRuleTemplates);
