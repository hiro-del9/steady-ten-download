(function(root){
'use strict';

const encoder=new TextEncoder();
function decodeBase64Url(value,expectedLength){
  if(typeof value!=='string'||!/^[A-Za-z0-9_-]+$/.test(value))throw new Error('INVALID_MANIFEST');
  const binary=atob(value.replace(/-/g,'+').replace(/_/g,'/'));
  const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
  if(bytes.length!==expectedLength)throw new Error('INVALID_MANIFEST');
  return bytes;
}
function validateManifest(m){
  if(!m||m.schemaVersion!==1||m.appName!=='穩步 10'||typeof m.appVersion!=='string'||!/^\d+\.\d+\.\d+$/.test(m.appVersion)||m.minAndroid!=='7.0')throw new Error('INVALID_MANIFEST');
  if(typeof m.fileName!=='string'||!/^steady-ten-\d+\.\d+\.\d+\.apk$/.test(m.fileName)||m.encryptedFile!==m.fileName+'.enc')throw new Error('INVALID_MANIFEST');
  if(!Number.isSafeInteger(m.size)||m.size<4||m.size>250*1024*1024||m.encryptedSize!==m.size+16||typeof m.sha256!=='string'||!/^[a-f0-9]{64}$/.test(m.sha256))throw new Error('INVALID_MANIFEST');
  const e=m.encryption;
  if(!e||e.algorithm!=='AES-256-GCM'||e.kdf!=='PBKDF2-HMAC-SHA256'||!Number.isSafeInteger(e.iterations)||e.iterations<310000||e.iterations>2100000||e.tagLength!==128)throw new Error('INVALID_MANIFEST');
  decodeBase64Url(e.salt,16);decodeBase64Url(e.iv,12);
  return m;
}
function additionalData(m){return encoder.encode(JSON.stringify([m.schemaVersion,m.appName,m.appVersion,m.minAndroid,m.fileName,m.size,m.sha256]));}
async function decryptPayload(encrypted,manifest,password,cryptoProvider=root.crypto){
  const m=validateManifest(manifest),bytes=encrypted instanceof Uint8Array?encrypted:new Uint8Array(encrypted);
  if(bytes.byteLength!==m.encryptedSize)throw new Error('INVALID_PAYLOAD');
  if(!cryptoProvider?.subtle)throw new Error('CRYPTO_UNAVAILABLE');
  const material=await cryptoProvider.subtle.importKey('raw',encoder.encode(password.trim()),'PBKDF2',false,['deriveKey']);
  const key=await cryptoProvider.subtle.deriveKey({name:'PBKDF2',salt:decodeBase64Url(m.encryption.salt,16),iterations:m.encryption.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const plain=await cryptoProvider.subtle.decrypt({name:'AES-GCM',iv:decodeBase64Url(m.encryption.iv,12),tagLength:128,additionalData:additionalData(m)},key,bytes);
  const hash=new Uint8Array(await cryptoProvider.subtle.digest('SHA-256',plain));
  const actual=Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('');
  if(plain.byteLength!==m.size||actual!==m.sha256)throw new Error('HASH_MISMATCH');
  return plain;
}

if(typeof module==='object'&&module.exports)module.exports={validateManifest,decryptPayload,additionalData};
if(typeof document==='undefined')return;

const $=id=>document.getElementById(id);
const form=$('unlock-form'),input=$('download-password'),toggle=$('toggle-password'),button=$('unlock-button'),status=$('download-status'),download=$('download-link'),lock=$('lock-button');
let manifest,objectUrl=null,busy=false;
function showStatus(message,error=false){status.textContent=message;status.classList.toggle('error',error);}
function setBusy(value){busy=value;form.setAttribute('aria-busy',String(value));input.disabled=value;toggle.disabled=value;button.disabled=value;button.textContent=value?'正在解鎖，請稍候…':'解鎖安裝檔 ↗';}
function clearUnlocked(){if(objectUrl)URL.revokeObjectURL(objectUrl);objectUrl=null;download.removeAttribute('href');download.hidden=true;lock.hidden=true;$('integrity-details').hidden=true;input.value='';input.type='password';toggle.textContent='顯示';toggle.setAttribute('aria-pressed','false');}
toggle.addEventListener('click',()=>{const visible=input.type==='password';input.type=visible?'text':'password';toggle.textContent=visible?'隱藏':'顯示';toggle.setAttribute('aria-pressed',String(visible));});
lock.addEventListener('click',()=>{clearUnlocked();showStatus('已清除本頁解鎖的檔案；已下載到裝置的檔案不受影響。');input.focus();});
window.addEventListener('pagehide',clearUnlocked);
form.addEventListener('submit',async event=>{
  event.preventDefault();if(busy||!manifest)return;
  const password=input.value.trim();if(!password){showStatus('請先輸入另行收到的下載密碼。',true);input.focus();return;}
  clearUnlocked();setBusy(true);showStatus('正在取得加密檔案…');
  try{
    const response=await fetch(manifest.encryptedFile,{cache:'no-store',credentials:'omit',redirect:'error'});
    if(!response.ok)throw new Error('DOWNLOAD_FAILED');
    const encrypted=await response.arrayBuffer();
    showStatus('正在本機解密及核對檔案，請稍候…');
    const plain=await decryptPayload(encrypted,manifest,password);
    objectUrl=URL.createObjectURL(new Blob([plain],{type:'application/vnd.android.package-archive'}));
    download.href=objectUrl;download.download=manifest.fileName;download.hidden=false;lock.hidden=false;
    $('file-sha256').textContent=manifest.sha256;$('integrity-details').hidden=false;
    showStatus('已解鎖，檔案核對成功。請按下方按鈕下載。');download.focus();
  }catch(error){
    clearUnlocked();
    if(error.message==='DOWNLOAD_FAILED'||error instanceof TypeError)showStatus('未能取得安裝檔。請檢查網路後再試，或重新載入本頁。',true);
    else showStatus('未能解鎖：密碼不正確，或檔案已損壞／版本已更新。請核對密碼並重新載入本頁後再試。',true);
  }finally{setBusy(false);}
});

(async()=>{
  if(!window.isSecureContext||!root.crypto?.subtle){$('release-info').textContent='Android 測試版';showStatus('此瀏覽器無法安全解密。請以最新版瀏覽器開啟 HTTPS 網址；本機測試可使用 localhost。直接開啟檔案或一般 HTTP 網址可能無法使用。',true);return;}
  try{
    const response=await fetch('manifest.json',{cache:'no-store',credentials:'omit',redirect:'error'});
    if(!response.ok)throw new Error('MANIFEST_FAILED');
    manifest=validateManifest(await response.json());
    $('release-info').textContent=`版本 ${manifest.appVersion} · Android ${manifest.minAndroid} 以上 · ${(manifest.size/1024/1024).toFixed(1)} MB`;
    setBusy(false);showStatus('準備好了。請輸入下載密碼。');
  }catch(error){$('release-info').textContent='暫時無法讀取版本資訊';showStatus('下載資料暫時無法使用。請重新載入本頁，或聯絡分享者更新檔案。',true);}
})();
})(globalThis);
