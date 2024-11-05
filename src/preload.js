// See the Electron documentation for details on how to use preload scripts:
// https://www.electronjs.org/docs/latest/tutorial/process-model#preload-scripts

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    saveJson: (jsonData) => ipcRenderer.send('save-json', jsonData),
    onSaveJsonResponse: (callback) => ipcRenderer.on('save-json-response', (event, response) => callback(response)),
    getUserName: () => ipcRenderer.invoke('get-username'),
    openAddFriendWindow: () => ipcRenderer.send('open-add-friend-window'),
    getUserToken: () => ipcRenderer.invoke('get-user-token'),
    openViewPendingFriendsWindow: () => ipcRenderer.send('open-view-pending-friends-window'),
    openViewFriendsWindow: () => ipcRenderer.send("open-view-friends-window"),
    // openChatroomWindow: () => ipcRenderer.send("open-chatroom-window"),
    openChatroomWindow: (friend, realFriendName, chatroomId, friendPublicKey, sk) => ipcRenderer.send('open-chatroom-window', { friend, realFriendName, chatroomId, friendPublicKey, sk}),
    onChatroomData: (callback) => ipcRenderer.on('chatroom-data', callback),
    generateRSAKeys: () => ipcRenderer.invoke("generate-rsa-keys"),
    saveMainUser: (user_data) => ipcRenderer.send('save-main-user', user_data),
    onSaveMainUser: (callback) => ipcRenderer.on('save-main-user-data', (event, response) => callback(response)),
    encryptMessage: (message, publicKey) => ipcRenderer.invoke('encrypt-message', message, publicKey),
    decryptMessage: (encrypted_message, private_key) => ipcRenderer.invoke('decrypt-message', encrypted_message, private_key),
    signMessage: (message, private_key) => ipcRenderer.invoke("sign-message", message, private_key),
    verifyMessage: (message, signature, public_key) => ipcRenderer.invoke("verify-message", message, signature, public_key),
    getUserPrivate: () => ipcRenderer.invoke('get-user-private'),
    getUserPublic: () => ipcRenderer.invoke('get-user-public'),
    getUserId: () => ipcRenderer.invoke('get-user-id'),
    generateSK: () => ipcRenderer.invoke("generate-sk"),
    convertSkToBuffer: (sk) => ipcRenderer.invoke("convert-sk-to-buffer", sk),
    convertIVToBuffer: (iv) => ipcRenderer.invoke("convert-iv-to-buffer", iv),
    
    
    encryptMessageUsingSK: (plainText, key) => ipcRenderer.invoke("encrypt-message-sk", plainText, key),
    decryptMessageUsingSK: (encryptedData, key, iv) => ipcRenderer.invoke("decrypt-message-sk", encryptedData, key, iv),


});