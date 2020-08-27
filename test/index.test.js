const assert = require('assert')
const encrypt = require('../src/index.js')
const path = require('path')

let cipherKey, publicKey, encryptedKey, decryptedKey
let privateKey = "d6d3710c0f16fafcfce5d4e1de712b875dd9e6eab4e05e0519ade677fe73a319"
let fileLocation = "/home/shubham/Documents/file.txt"
let outputFileLocation = "./src/results.txt"

it('should get public key', function () {
    publicKey = encrypt.getPublicKey(privateKey)
    assert(publicKey!=null)
});

describe("Test for encrypting file and key",  () => {

    it('should generate symmetric key', function () {
        cipherKey = encrypt.generateCipherKey("password")
        assert(cipherKey!=null);
    });

    it('should encrypt file', async () => {
        const status = await encrypt.encryptFile(fileLocation,cipherKey)
        assert.strictEqual(true,status)
    }).timeout(4000);

    it('should encrypt symmetric key', async () =>{
        encryptedKey = await encrypt.encryptKey(publicKey,cipherKey)
        assert(encryptedKey!=null)
    });

})

describe("Test for decrypting file and key",  () => {

    it('should decrypt symmetric key', async ()=>{
        decryptedKey = await encrypt.decryptKey(privateKey,encryptedKey)
        assert(decryptedKey!=null)
    });

    it('should decrypt file',  () => {
        const status = encrypt.decryptFile(path.join(fileLocation + ".enc"),cipherKey,outputFileLocation)
        assert.strictEqual(true,status)
    });

})
