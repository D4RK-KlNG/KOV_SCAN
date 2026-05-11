const crypto=require("crypto")

const KEY_CONFIG={
version:"1.0.0",
kdf:{algorithm:"sha512",iterations:20000,keyLength:32,digest:"sha512"},
salt:crypto.randomBytes(16),
seeds:Array.from({length:14},()=>crypto.randomBytes(7).toString("hex")),
cipher:{algorithm:"aes-256-cbc",ivLength:16}
}

function generateSeed(len=14){
const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
let r=""
for(let i=0;i<len;i++)r+=chars[crypto.randomInt(chars.length)]
return r
}

function deriveKey(seed,salt){
return crypto.pbkdf2Sync(seed,salt,KEY_CONFIG.kdf.iterations,KEY_CONFIG.kdf.keyLength,KEY_CONFIG.kdf.digest)
}

function createCryptoContext(i=0,random=false){
const seed=random?generateSeed(14):KEY_CONFIG.seeds[i%KEY_CONFIG.seeds.length]
const key=deriveKey(seed,KEY_CONFIG.salt)
return{key,seed,algorithm:KEY_CONFIG.cipher.algorithm,ivLength:KEY_CONFIG.cipher.ivLength}
}

module.exports={KEY_CONFIG,deriveKey,createCryptoContext,generateSeed}
