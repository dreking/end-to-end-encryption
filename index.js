// Algorithm used => aes-256-cbc

const crypto = require('crypto');
const algorithm = 'aes-256-cbc';

// Initialize and generating Alice Diffier Hellman Keys
const alice = crypto.getDiffieHellman('modp15');
alice.generateKeys();

// Initialize and generating Bob Diffier Hellman Keys
const bob = crypto.getDiffieHellman('modp15');
bob.generateKeys();

// This is how to generate a shared secret key between Alice and Bob
// Public Key may come from server or a file
// In this example, it is coming from the above code
const aliceSecretKey = alice.computeSecret(bob.getPublicKey(), null, 'hex');
const bobSecretKey = bob.computeSecret(alice.getPublicKey(), null, 'hex');

const encrypt = (text) => {
	// Converting Alice Shared Secret Key to 32 bits
	const key = crypto.scryptSync(aliceSecretKey, 'salt', 32);
	// Initializing Initial Vector(IV) value to 16 bytes
	const iv = crypto.randomBytes(16);

	// Structuring message to be sent
	const data = JSON.stringify({ text: text });

	// Initiating Cipher Encryption and adding IV
	let cipher = crypto.createCipheriv(algorithm, key, iv);
	// Adding data to the cypher
	let encrypted = cipher.update(data);
	// Finalizing the cypher
	encrypted = Buffer.concat([encrypted, cipher.final()]);
	return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
};

const decrypt = (text) => {
	// Converting Bob Shared Secret Key to 256 bits
	const key = crypto.scryptSync(bobSecretKey, 'salt', 32);

	// Creating buffer of iv and text string from encrypted text
	const iv = Buffer.from(text.iv, 'hex');
	let encryptedText = Buffer.from(text.encryptedData, 'hex');
	// Initiating Decypher Decryption and adding IV
	let decipher = crypto.createDecipheriv(algorithm, key, iv);
	// Adding buffer encrypted string to the Decypher
	let decrypted = decipher.update(encryptedText);
	// Finalizing the Decypher
	decrypted = Buffer.concat([decrypted, decipher.final()]);
	return JSON.parse(decrypted);
};

const aliceSentEncryptedMessage = encrypt('Some serious stuff');
console.log(aliceSentEncryptedMessage);
const aliceDecryptedMessageByBob = decrypt(aliceSentEncryptedMessage);
console.log(aliceDecryptedMessageByBob);
