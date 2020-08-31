const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const zlib = require('zlib')
const AppendInitVect = require('./appendInitVect')
const eccrypto = require("eccrypto")


let cipherKey, publicKey, encryptedKey, decryptedKey,encryptedData


const encryptFile = function (file) {
    try {
        const initVect = crypto.randomBytes(16)
        const readStream = fs.createReadStream(file)
        const cipher = crypto.createCipheriv('aes256', cipherKey, initVect)
        const appendInitVect = new AppendInitVect(initVect)
        const writeStream = fs.createWriteStream(path.join(file + ".enc"))
        const gzip = zlib.createGzip()

        return new Promise((resolve, reject) =>{
            readStream
                .pipe(gzip)
                .pipe(cipher)
                .pipe(appendInitVect)
                .pipe(writeStream).on('finish', () =>{
                resolve(true)
            })
        })
    }catch (err) {
        console.error("Error while encrypting file",err)
        return false
    }
}

/**
 * Decrypts the file
 * @param file: {String} File location
 * @param cipherKey: {Buffer} Symmetric Key
 * @param outputLocation: {String} decrypted file location
 * @returns {boolean}
 */

const decryptFile = function(file,cipherKey,outputLocation){
    try {
        const readInitVect = fs.createReadStream(file, {end: 15});

        let initVect;
        readInitVect.on('data', (chunk) => {
            initVect = chunk;
        });

        readInitVect.on('close', () => {
            const readStream = fs.createReadStream(file, {start: 16});
            const decipher = crypto.createDecipheriv('aes256', cipherKey, initVect);
            const unzip = zlib.createUnzip();
            const writeStream = fs.createWriteStream(outputLocation);

            readStream
                .pipe(decipher)
                .pipe(unzip)
                .pipe(writeStream);
        });
        return true
    }catch (err) {
        console.error("Error while decrypting file:",err)
        return false
    }
}


/**
 * Encrypts Symmetric key used for encrypting file
 * @param publicKey: {Buffer}
 * @param cipherKey: {Buffer} Symmetric Key
 * @returns {Promise<unknown>|null}
 */
const encryptKey = function(){
    try {
        const iv = Buffer.alloc(16);
        iv.fill(5);
        const ephemPrivateKey = Buffer.alloc(32);
        ephemPrivateKey.fill(4);
        const encOpts = {ephemPrivateKey: ephemPrivateKey, iv: iv};
        //return new Promise((resolve) => {
            eccrypto.encrypt(publicKey, cipherKey, encOpts).then(function (result) {
                encryptedKey = result;
                console.log("encryptedKey:",encryptedKey)
                //resolve(result);
            })
        //})
    }catch(err) {
        console.error("Error while encrypting key:",err)
        return null
    }

}

/**
 * Get public key from private key
 * @param privateKey: {String}
 * @returns {null|Buffer}
 */
const getPublicKey = function (privateKey){
    try {
        publicKey = eccrypto.getPublic(Buffer.from(privateKey, "hex"))
        console.log("PublicKey:",publicKey)
        return publicKey
    }catch(err){
        console.error("Error while extracting public key:",err)
        return null;
    }
}

/**
 * Decrypts Symmetric key used for encrypting file
 * @param privateKey: {String}
 * @param encryptedKey: {Buffer}
 * @returns {Promise<unknown>|null}
 */
const decryptKey = function(privateKey){
    try {
        eccrypto.decrypt(Buffer.from(privateKey, "hex"), encryptedKey)
            .then(function (decryptedKey) {
                console.log('Decrypted key:',decryptedKey)
            });
    }catch(err){
        console.error("Error while decrypting key:",err)
        return null
    }
}

/**
 * Create symmetric key for file encryption
 * @param password: {String}
 * @returns {null|Buffer}
 */
const generateCipherKey = function(password){
    try {
        cipherKey = crypto.createHash('sha256').update(password).digest();
        console.log("Key:",cipherKey)
        return cipherKey
    }catch (err) {
        console.error("Error while generating symmetric key:",err)
        return null
    }
}

const uploadFile = function(e){
    let files = e.target.files
    console.log("files:",files[0])
    let reader = new FileReader()
    reader.readAsText(files[0])
    console.log("Loading text file:")

    reader.onload = (val)=>{
        const result = val.target.result
        console.log("File loaded...")
        const hashBefore = crypto.createHash("sha256").update(result.toString()).digest()
        console.log("hashBeforeEncryption:",hashBefore)

        let iv = crypto.randomBytes(16);
        console.log("AESKey:",cipherKey)
        const cipher = crypto.createCipheriv('aes256', cipherKey, iv);
        encryptedData= Buffer.concat([iv, cipher.update(Buffer.from(result.toString())), cipher.final()]);
        console.log("encryptedData:", encryptedData);

        iv = encryptedData.slice(0,16)
        encryptedData = encryptedData.slice(16)
        const decipher = crypto.createDecipheriv("aes256",cipherKey,iv)
        const decryptedData = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
        const hashAfter = crypto.createHash("sha256").update(decryptedData.toString()).digest();
        console.log("hashAfterDecryption:",hashAfter)
    }

    reader.onerror = (e)=>{
        console.log("reader error:",e)
    }
}


module.exports = {
    encryptFile,
    decryptFile,
    generateCipherKey,
    encryptKey,
    decryptKey,
    getPublicKey,
    uploadFile
}
