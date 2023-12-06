/*
   Javascript version of CryptoJS
   <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>

*/

async function encrypt(password, plainMessage) {
    const salt = crypto.getRandomValues(new Uint8Array(16)); // Random salt of 16 bytes
    const secret = await getSecretKey(password, salt);

    const iv = crypto.getRandomValues(new Uint8Array(12)); // Random IV of 12 bytes
    const cipher = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        secret,
        new TextEncoder().encode(plainMessage)
    );

    const encryptedMessageByte = new Uint8Array(cipher);
    const tag = encryptedMessageByte.slice(-16);
    const cipherByte = new Uint8Array([...iv, ...salt, ...encryptedMessageByte.slice(0, -16), ...tag]);

    const encodedCipherByte = btoa(String.fromCharCode(...cipherByte));
    return encodedCipherByte;
}

async function decrypt(password, cipherMessage) {
    const decodedCipherByte = new Uint8Array([...atob(cipherMessage)].map(char => char.charCodeAt(0)));

    const iv = decodedCipherByte.slice(0, 12);
    const salt = decodedCipherByte.slice(12, 28);
    const tag = decodedCipherByte.slice(-16);
    const encryptedMessageByte = decodedCipherByte.slice(28, -16);

    const secret = await getSecretKey(password, salt);
    
    try {
        const decryptedMessageByte = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            secret,
            new Uint8Array([...encryptedMessageByte, ...tag])
        );

        return new TextDecoder().decode(decryptedMessageByte);
    } catch (error) {
        console.error('Decryption Error:', error);
        throw error;
    }
}




async function getSecretKey(password, salt) {
    const passwordBuffer = new TextEncoder().encode(password);
    const importedKey = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );

    const keyMaterial = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 65536,
            hash: 'SHA-256',
        },
        importedKey,
        256 // Ensure 256-bit key length for AES-GCM
    );

    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        true, // Make sure to set extractable to true
        ['encrypt', 'decrypt']
    );

    return key;
}



// Example usage
const secretKey = 'yourSecretKey';
const plainText = 'M0993000353';

// console.log("------ AES-GCM Encryption ------");
// encrypt(secretKey, plainText)
//     .then(cipherText => {
//         console.log(`encryption input: ${plainText}`);
//         console.log(`encryption output: ${cipherText}`);
//     })
//     .catch(error => console.error('Error:', error));


console.log("\n------ AES-GCM Decryption ------");
const cipherText = "IxFKJveIP6o2bT8agFuoA0Kr8eJTP41CxBHTpoQcdYtxdGxVJmRZ8UWN2acIm3+stb1KKqdeX12C5XzU";
decrypt(secretKey, cipherText)
    .then(decryptedText => {
        console.log(`decryption input: ${cipherText}`);
        console.log(`decryption output: ${decryptedText}`);
    })
//     .catch(error => console.error('Error:', error));   
