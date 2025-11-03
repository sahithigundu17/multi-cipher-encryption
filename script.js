// === Internal state ===
let fileText = "";        // hidden uploaded file content (not displayed)
let storedCipher = "";    // last ciphertext produced by encryption (Base64)
let selectedAlgo = "";    // last selected algorithm (used for decryption)

// === File upload handling (hidden) ===
document.getElementById('fileInput')?.addEventListener('change', function () {
  const file = this.files[0];
  if (!file) return;

  // ~500 words guard (approx): use 100 KB as rough upper bound
  if (file.size > 100 * 1024) {
    alert("File too large! Please upload a file with ≤ 500 words.");
    this.value = '';
    fileText = "";
    return;
  }

  const reader = new FileReader();
  reader.onload = function (e) {
    fileText = e.target.result.replace(/\r\n/g, '\n'); // store internally
    alert("✅ File uploaded successfully (content stored internally).");
  };
  reader.readAsText(file);
});

// === Helper: get input text (manual or file) ===
function getManualOrFileText() {
  const manual = document.getElementById('inputText').value.trim();
  return manual || fileText || "";
}

// === Caesar Cipher (preserve case & non-alpha) ===
function caesarEncrypt(text, shift = 3) {
  return text.replace(/[a-zA-Z]/g, c => {
    const base = c === c.toUpperCase() ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
}
function caesarDecrypt(text, shift = 3) {
  return caesarEncrypt(text, 26 - shift);
}

// === Substitution Cipher (preserve case & non-alpha) ===
const alphabet = 'abcdefghijklmnopqrstuvwxyz';
const subKey = 'zyxwvutsrqponmlkjihgfedcba'; // reversed alphabet
function substitutionEncrypt(text) {
  return text.split('').map(ch => {
    const lower = ch.toLowerCase();
    if (!/[a-z]/i.test(lower)) return ch;
    const mapped = subKey[alphabet.indexOf(lower)];
    return ch === lower ? mapped : mapped.toUpperCase();
  }).join('');
}
function substitutionDecrypt(text) {
  return text.split('').map(ch => {
    const lower = ch.toLowerCase();
    if (!/[a-z]/i.test(lower)) return ch;
    const mapped = alphabet[subKey.indexOf(lower)];
    return ch === lower ? mapped : mapped.toUpperCase();
  }).join('');
}

// === DES (CryptoJS) - use explicit Base64 ciphertext format ===
const desUtf8Key = CryptoJS.enc.Utf8.parse("mysecret1"); // 8 chars
function desEncrypt(plainText) {
  const encrypted = CryptoJS.DES.encrypt(
    CryptoJS.enc.Utf8.parse(plainText),
    desUtf8Key,
    { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }
  );
  // return Base64 string of raw ciphertext (portable)
  return CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
}
function desDecrypt(base64Cipher) {
  // Accept either Base64 string or possibly an OpenSSL-format string:
  try {
    const cipherParams = { ciphertext: CryptoJS.enc.Base64.parse(base64Cipher) };
    const decrypted = CryptoJS.DES.decrypt(cipherParams, desUtf8Key, {
      mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch (err) {
    return "Error during DES decryption: invalid ciphertext or key.";
  }
}

// === AES (CryptoJS) - explicit Base64 ciphertext format ===
const aesUtf8Key = CryptoJS.enc.Utf8.parse("1234567890123456"); // 16 chars
function aesEncrypt(plainText) {
  const encrypted = CryptoJS.AES.encrypt(
    CryptoJS.enc.Utf8.parse(plainText),
    aesUtf8Key,
    { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }
  );
  return CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
}
function aesDecrypt(base64Cipher) {
  try {
    const cipherParams = { ciphertext: CryptoJS.enc.Base64.parse(base64Cipher) };
    const decrypted = CryptoJS.AES.decrypt(cipherParams, aesUtf8Key, {
      mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch (err) {
    return "Error during AES decryption: invalid ciphertext or key.";
  }
}

// === SHA-1 Hash (one-way) ===
async function sha1Hash(text) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-1', enc.encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// === UI helpers ===
function setOutput(text) {
  document.getElementById('outputText').value = text;
}

// === Encrypt button handler ===
document.getElementById('encryptBtn').addEventListener('click', async () => {
  selectedAlgo = document.getElementById('algorithm').value;
  const input = getManualOrFileText();
  if (!input) {
    alert("Please type text OR upload a .txt file (<= 500 words).");
    return;
  }

  let cipher = "";
  switch (selectedAlgo) {
    case 'Caesar Cipher':
      cipher = caesarEncrypt(input);
      break;
    case 'Substitution Cipher':
      cipher = substitutionEncrypt(input);
      break;
    case 'DES':
      cipher = desEncrypt(input); // Base64
      break;
    case 'AES':
      cipher = aesEncrypt(input); // Base64
      break;
    case 'SHA-1 Hash':
      const h = await sha1Hash(input);
      setOutput(h);
      storedCipher = ""; // no reversible cipher stored
      return;
    default:
      alert("Unknown algorithm");
      return;
  }

  // store ciphertext internally for later decrypt
  storedCipher = cipher;
  setOutput(cipher);
//   alert("Encryption complete — ciphertext stored internally for decryption.");
});

// === Decrypt button handler ===
document.getElementById('decryptBtn').addEventListener('click', async () => {
  // Use storedCipher if exists; otherwise fallback to manual input (user pasted ciphertext)
  const manual = document.getElementById('inputText').value.trim();
  let cipherToUse = storedCipher || manual;

  if (!cipherToUse) {
    alert("No ciphertext available: first Encrypt (uses typed text or uploaded file) or paste ciphertext into the input box.");
    return;
  }

  // Ensure algorithm matches the one used to produce storedCipher (if stored)
  const algo = document.getElementById('algorithm').value;
  let plain = "";

  // If there's storedCipher but algorithm changed since encrypt, warn user
  if (storedCipher && algo !== selectedAlgo) {
    if (!confirm("You changed the algorithm since encryption. Decryption may fail. Continue?")) {
      return;
    }
  }

  switch (algo) {
    case 'Caesar Cipher': 
      plain = caesarDecrypt(cipherToUse);
      break;
    case 'Substitution Cipher':
      plain = substitutionDecrypt(cipherToUse);
      break;
    case 'DES':
      plain = desDecrypt(cipherToUse);
      break;
    case 'AES':
      plain = aesDecrypt(cipherToUse);
      break;
    default:
      plain = 'Decryption not applicable for hash functions!';
  }

  setOutput(plain);
  // Optionally clear storedCipher after successful decrypt to avoid confusion:
  // storedCipher = "";
});

// === Hash button handler (explicit) ===
document.getElementById('hashBtn').addEventListener('click', async () => {
  const input = getManualOrFileText();
  if (!input) {
    alert("Please type text OR upload a .txt file to hash.");
    return;
  }
  const h = await sha1Hash(input);
  setOutput(h);
  storedCipher = ""; // not reversible
});

// === Download output handler ===
document.getElementById('downloadBtn')?.addEventListener('click', () => {
  const output = document.getElementById('outputText').value;
  if (!output) {
    alert("No output to download!");
    return;
  }

  // choose filename based on whether storedCipher exists and last op
  const algo = document.getElementById('algorithm').value;
  let fname = "output.txt";
  if (storedCipher && (algo === selectedAlgo)) {
    // encryption likely produced the output
    fname = `encrypted_${algo.replace(/\s+/g, "")}.txt`;
  } else if (algo === 'DES' || algo === 'AES' || algo === 'Caesar Cipher' || algo === 'Substitution Cipher') {
    fname = `processed_${algo.replace(/\s+/g, "")}.txt`;
  } else if (algo === 'SHA-1 Hash') {
    fname = `sha1_hash.txt`;
  }

  const blob = new Blob([output], { type: "text/plain" });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = fname;
  link.click();
  URL.revokeObjectURL(link.href);
});
