import React,{Component} from 'react';
const e2eEncrypt = require('../lib/e2e-encrypt.js');

class E2EEncrypt extends Component {

    render() {
        return (
            <div className="e2e_encrypt">
                <button>Encrypt file</button>
                <button>Decrypt file</button>
                <button onClick={()=>e2eEncrypt.getPublicKey("d6d3710c0f16fafcfce5d4e1de712b875dd9e6eab4e05e0519ade677fe73a319")}>Get Public Key</button>
                <button onClick={()=>e2eEncrypt.generateCipherKey("password")}>Generate Key</button>
                <button onClick={()=>e2eEncrypt.encryptKey()}>Encrypt Key</button>
                <button onClick={()=>e2eEncrypt.decryptKey("d6d3710c0f16fafcfce5d4e1de712b875dd9e6eab4e05e0519ade677fe73a319")}>Decrypt Key</button>
                <input type='file' name='file' onChange={(e)=>e2eEncrypt.uploadFile(e)}/>
            </div>
        )
    }
}

export default E2EEncrypt;
