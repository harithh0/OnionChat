const { app, BrowserWindow,ipcMain, dialog } = require('electron');
const path = require('node:path');

const fs = require('fs');
const forge = require('node-forge');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const { spawn } = require('child_process');
const { exec } = require('child_process');
const { createProxyMiddleware } = require('http-proxy-middleware');





// tor config:
const torRequest = require('tor-request');
const axios = require('axios');
let torProcess;
let loadingWindow;


if (require("electron-squirrel-startup")){
  app.quit();
}

torRequest.setTorAddress('127.0.0.1', 9050);


async function torsend(url, options) {
  const { method, headers, data } = options;

  return new Promise((resolve, reject) => {
      torRequest.request({
          url,
          method,
          headers,
          body: JSON.stringify(data),
      }, (error, response, body) => {
          if (error) return reject(error);
          resolve({ status: response.statusCode, data: body });
      });
  });
}

ipcMain.handle('torsend', async (event, url, options) => {
  try {
      const response = await torsend(url, options);
      return response;
  } catch (error) {
      console.error('Tor request failed:', error);
      throw error;
  }
});



// tor config end


function checkTorInstallation() {
  return new Promise((resolve, reject) => {
    exec('tor --version', (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout.includes('Tor'));
      }
    });
  });
}

function checkPortUsage(port) {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        resolve(true);
      } else {
        reject(err);
      }
    });

  });
}


app.on('ready', async () => {
  try {
    const isTorInstalled = await checkTorInstallation();
    if (!isTorInstalled) {
      dialog.showErrorBox('Tor Not Installed', 'Tor is not installed on your system. Please install Tor to use this application.');
      app.quit();
    } 
  } catch (error) {
    dialog.showErrorBox('Error', 'An error occurred while checking for Tor installation.');
    app.quit();
  }
  try {
    const isPort3000InUse = await checkPortUsage(3000);
    if (isPort3000InUse) {
      dialog.showErrorBox('Server Error', 'Failed to start local proxy server. (PORT 3000 already in use)');
      app.quit();
    } 
  } catch (error) {
    dialog.showErrorBox('Error', 'An error occurred while checking port usage.');
    app.quit();
  }
  try {
    const isPort3051InUse = await checkPortUsage(3051);
    if (isPort3051InUse) {
      dialog.showErrorBox('Server Error', 'Failed to start local proxy server. (PORT 3051 already in use)');
      app.quit();
    } 
  } catch (error) {
    dialog.showErrorBox('Error', 'An error occurred while checking port usage.');
    app.quit();
  }



});



// for websocket tor proxy to work
const express = require('express');
const WebSocket = require('ws');
const { SocksProxyAgent } = require('socks-proxy-agent');
const http = require('http');
const url = require('url');
const { kill } = require('node:process');

const express_app = express();
const server = http.createServer(express_app);
const wss = new WebSocket.Server({ noServer: true });


server.on('upgrade', (request, socket, head) => {
  const { pathname, query } = url.parse(request.url, true);

  // Extract the target WebSocket URL from the query string
  const target = query.target;
  if (!target) {
      socket.destroy(); // Close the connection if no target is provided
      return;
  }

  const proxyAgent = new SocksProxyAgent('socks5h://127.0.0.1:9050'); // Tor proxy
  const proxySocket = new WebSocket(target, { agent: proxyAgent });

  // Upgrade the WebSocket connection
  wss.handleUpgrade(request, socket, head, (ws) => {
      proxySocket.on('message', (message) => {
        const originalJsonObject = JSON.parse(message.toString('utf-8')); 
        // console.log("recievd message:" + JSON.stringify(originalJsonObject))
        ws.send(JSON.stringify(originalJsonObject)); // Forward messages from target to client
      });

      ws.on('message', (message) => {

        // must convert binary to string 
        // const originalJsonObject = JSON.parse(message.toString('utf-8')); <- need to also make sure you turn string into json if this is used
        const originalString = message.toString('utf-8');

        // console.log("message to send:", originalString);


        if (proxySocket.readyState === WebSocket.OPEN)
          proxySocket.send(originalString); // Forward messages from client to target
        });

      proxySocket.on('close', () => ws.close());
      ws.on('close', () => proxySocket.close());

      proxySocket.on('error', (err) => {
        // console.error('WebSocket error:', err);
        ws.close();
      });
      
      ws.on('error', (err) => {
        // console.error('WebSocket error:', err);
        proxySocket.close();
      });
      
  });
});
server.listen(3000, () => {
  console.log('Proxy server running on http://localhost:3000');
}).on('error', (err) => {
  console.error('Failed to start server:', err);
  dialog.showErrorBox('Server Error', 'Failed to start local proxy server. (PORT 3000 already in use)');
  app.quit();

});


const express_http_api = express();
const server_http_api= http.createServer(express_http_api);
server_http_api.setMaxListeners(20);
const proxyAgent = new SocksProxyAgent('socks5h://127.0.0.1:9050'); // Tor proxy

express_http_api.use('/', (req, res, next) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    res.status(400).send('Missing url query parameter');
    return;
  }
  const parsedUrl = url.parse(targetUrl);
  const newUrl = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;

  createProxyMiddleware({
    target: newUrl,
    changeOrigin: true,
    agent: proxyAgent,
    pathRewrite: (path, req) => {
      // Remove the 'url' query parameter from the path
      const queryIndex = path.indexOf('?');
      if (queryIndex !== -1) {
        const queryParams = new URLSearchParams(path.substring(queryIndex + 1));
        queryParams.delete('url');
        return path.substring(0, queryIndex) + (queryParams.toString() ? '?' + queryParams.toString() : '');
      }
      return path;
    },
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader('Host', parsedUrl.host);
    }
  })(req, res, next);
});

server_http_api.listen(3051, () => {
  console.log('Proxy server running on http://localhost:3051');
}).on('error', (err) => {
  console.error('Failed to start server:', err);
  dialog.showErrorBox('Server Error', 'Failed to start local proxy server. (PORT 3051 already in use)');
  app.quit();
});


// Get the path to the user's application data directory
// will be stored in /.config/appname for linux
const userDataPath = app.getPath('userData');

//console.log(userDataPath)
// Ensure the directory exists
if (!fs.existsSync(userDataPath)) {
  fs.mkdirSync(userDataPath, { recursive: true });
}

// Construct the path to the database file
const dbPath = path.join(userDataPath, 'data.db');

// Initialize the SQLite database
let db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    //console.error('Failed to open database:', err.message);
  } else {
    //console.log('Connected to the SQLite database.');
  }
});




function createLoadingWindow() {
  loadingWindow = new BrowserWindow({
      width: 400,
      height: 300,
      frame: false,
      alwaysOnTop: true,
      webPreferences: {
          nodeIntegration: true,
      },
  });

  loadingWindow.loadFile(path.join(__dirname, './screens/loading.html'));


  loadingWindow.on('closed', function () {
      loadingWindow = null;
  });
}




function startTor() {
  return new Promise((resolve, reject) => {
    torProcess = spawn('tor');
    torProcess.stdout.on('data', (data) => {
      console.log(`Tor: ${data}`);
      if (data.toString().includes('Bootstrapped 100%')) {
        resolve();
      }
    });
    torProcess.stderr.on('data', (data) => {
      console.error(`Tor error: ${data}`);
    });
    torProcess.on('close', (code) => {
      console.log(`Tor process exited with code ${code}`);
      dialog.showErrorBox('Tor Closed', 'Tor process has been closed. The application will now exit for security.');
      app.quit();
    });
  });
}



async function stopTor() {
  if (torProcess) {
    return new Promise((resolve) => {
      torProcess.on('exit', resolve); // Ensure app waits for Tor to exit
      torProcess.kill('SIGINT'); // Try graceful shutdown
      setTimeout(() => torProcess.kill('SIGKILL'), 5000); // Force quit if needed
    });
  }
}



function killProcessOnPort(port) {
  return new Promise((resolve, reject) => {
    exec(`fuser -k ${port}/tcp`, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

// runs when exiting fully ctrl-C
app.on('before-quit', async () => {
  await stopTor();
  await killProcessOnPort(3000);
  await killProcessOnPort(3051);
});


// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', async () => {
  if (process.platform !== 'darwin') {
    db.close();
    
    try {
      await stopTor();
      await killProcessOnPort(3000);
      await killProcessOnPort(3051);
    } catch (error) {
      console.error('Error while stopping processes:', error);
    }
    app.quit();
  }
});


function getTorExecutablePath() {
  const platform = process.platform;
  let torExecutable = '';

  if (platform === 'win32') {
      torExecutable = 'tor-win.exe';
  } else if (platform === 'darwin') {
      torExecutable = 'tor-mac';
  } else if (platform === 'linux') {
      torExecutable = 'tor-linux';
  }

  return path.join(__dirname, 'resources', 'tor', torExecutable);
}


// app.on('ready', () => {
//   createLoadingWindow();
//   startTor()
//       .then(() => {
//           if (loadingWindow) {
//               loadingWindow.close();
//           }
//           createMainWindow();
//       })
//       .catch((error) => {
//           //console.error('Failed to start Tor:', error);
//           if (loadingWindow) {
//               loadingWindow.close();
//           }
//           app.quit();
//       });
// });



db.run(`CREATE TABLE IF NOT EXISTS main_user (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  token TEXT NOT NULL,
  public_key NOT NULL,
  private_key TEXT NOT NULL

)`);




function insertMainUser(user_id, username, token, public_key, private_key) {
  db.run(`INSERT INTO main_user (user_id, username, token, public_key, private_key) VALUES (?, ?, ?, ?, ?)`, 
    [user_id, username, token, public_key, private_key], 
    function(err) {
      if (err) {
        return //console.error(err.message);
      }
      //console.log(`A row has been inserted with rowid ${this.lastID}`);
    }
  );
}

function getMainUser() {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM main_user LIMIT 1`, [], (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
}


ipcMain.on('save-main-user', (event, user_data) => {

  const user_token = user_data.token
  const username = user_data.user_data.username
  const user_id = user_data.user_data.id;
  const user_public_key = user_data.user_data.public_key;
  const user_private_key = user_data.private_key;
  insertMainUser(user_id, username, user_token, user_public_key, user_private_key);
});






function checkForToken() {

}





async function getUserName() {
  const user_data = await getMainUser();
  const username = user_data.username
  return username;
}


async function getUserPrivate() {
  const user_data = await getMainUser();
  const username = user_data.private_key
  return username;
}

async function getUserId() {
  const user_data = await getMainUser();
  const user_id = user_data.id
  return user_id;
}





async function getUserPublic() {
  const user_data = await getMainUser();
  const username = user_data.public_key
  return username;
}

async function getUserToken() {
  const user_data = await getMainUser();
  const token = user_data.token
  return token;

}




function generateRSAKeys() {
  return new Promise((resolve, reject) => {
      forge.pki.rsa.generateKeyPair({ bits: 3072, workers: 2 }, (err, keypair) => {
          if (err) {
              reject(err);
          } else {
              const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
              const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
              resolve({ publicKey: publicKeyPem, privateKey: privateKeyPem });
          }
      });
  });
}


async function generateSK() {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(32, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(buffer);
      }
    });
  });
}


async function convertSkToBuffer(sk){
  const skBuffer = Buffer.from(sk, 'hex'); // converts hex string to binary (buffer)
  return skBuffer;
}


async function convertIVToBuffer(iv){
  const ivBuffer = Buffer.from(iv, 'hex'); // converts hex string to binary (buffer)
  return ivBuffer;
}

ipcMain.handle('encrypt-message-sk', (event, plainText, key) => {
  return encryptMessageUsingSK(plainText, key);
});



ipcMain.handle('decrypt-message-sk', (event, encryptedData, key, iv) => {
  return decryptMessageUsingSK(encryptedData, key, iv);
});

async function encryptMessageUsingSK(plainText, key) {
  //console.log("key", key)
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits) for AES-256 encryption.');
  }
  
  const iv = crypto.randomBytes(16); // Generate a random initialization vector (IV)

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
}


function encryptFile(fileData, key) {
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);

  let encryptedData = cipher.update(Buffer.from(fileData));
  encryptedData = Buffer.concat([encryptedData, cipher.final()]);

  return {
    encryptedData: encryptedData.toString('base64'),
    iv: iv.toString('base64'),
  };
}

async function decryptFile(encryptedData, key, iv) {
  //console.log("key", key);
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits) for AES-256 decryption.');
  }
  
  const ivBuffer = Buffer.from(iv, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuffer);

  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

ipcMain.handle('encrypt-file', async (event, fileData, key) => {
  return encryptFile(fileData, key);
});


ipcMain.handle('decrypt-file', async (event, encryptedData, key, iv) => {

  return decryptFile(encryptedData, key, iv);
  
});


ipcMain.handle('convert-arraybuffer-to-buffer', (event, arrayBuffer) => {
  return Buffer.from(arrayBuffer);
});

async function getFilePath(file){
  const filePath = file.path;
  return filePath;
}

ipcMain.handle('get-file-path', async (event, file) => {
  return getFilePath(file);
});

function decryptMessageUsingSK(encryptedData, key, iv) {

  // encrypted data must be in hex format!!

  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits) for AES-256 decryption.');
  }
  if (iv.length !== 16) {
    throw new Error('IV must be 16 bytes for AES-256-CBC decryption.');
  }
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}



(async () => {
  const key = await generateSK(); 
  const keyHex = key.toString('hex');
  //console.log('Generated Key:', keyHex);
  
  const result = await encryptMessageUsingSK('Hello, World!', key);
  //console.log('Encrypted Text:', result.encryptedData);
  //console.log('IV:', result.iv);


  const ivBuffer = Buffer.from(result.iv, 'hex');
  //console.log("ivBuffer", ivBuffer)
  const decryptedM = await decryptMessageUsingSK(result.encryptedData, key, ivBuffer)
  //console.log("Decrypted text:", decryptedM)
})();


function encryptMessage(message, public_key){
  const encryptedMessage = crypto.publicEncrypt(public_key, Buffer.from(message));
  return encryptedMessage.toString('base64'); // binary to base64 (text) format (makes it easier to transport over the internet HTTP, JSON)  | proviedes compatbility between devices
}

function decryptMessage(encrypted_message, private_key){
  const encryptedMessageBuffer = Buffer.from(encrypted_message, "base64"); // takes a base64 encrypted text
  const decryptedMessage = crypto.privateDecrypt(private_key, encryptedMessageBuffer);
  return decryptedMessage.toString('utf8'); // takes it in decmial and converts it into human readable string format

}

function signMessage(message, private_key){
  const signer = crypto.createSign('sha256');
  signer.update(message);
  signer.end();
  const signature = signer.sign(private_key, 'base64');
  return signature;
}

function verifyMessage(message, signature, public_key){
  const verifier = crypto.createVerify('sha256');
  verifier.update(message);
  verifier.end();
  const signatureBuffer = Buffer.from(signature, 'base64');
  const isVerified = verifier.verify(public_key, signatureBuffer);
  return isVerified;

}

ipcMain.handle('verify-message', (event, message, signature, public_key) => {
  return verifyMessage(message, signature, public_key);
});

ipcMain.handle('sign-message', (event, message, private_key) => {
  return signMessage(message, private_key);
});


ipcMain.handle('decrypt-message', (event, encrypted_message, private_key) => {
  return decryptMessage(encrypted_message, private_key);
});


ipcMain.handle('encrypt-message', (event, message, public_key) => {
  return encryptMessage(message, public_key);
});

ipcMain.handle('convert-sk-to-buffer', (event, sk) => {
  return convertSkToBuffer(sk);
});




ipcMain.handle('convert-iv-to-buffer', (event, iv) => {
  return convertIVToBuffer(iv);
});
ipcMain.handle('generate-rsa-keys', () => {
  return generateRSAKeys();
});

ipcMain.handle("generate-sk", () => {
  return generateSK();

})





if (require('electron-squirrel-startup')) {
  app.quit();
}


ipcMain.handle('get-username', () => {
  return getUserName();
});

ipcMain.handle('get-user-token', () => {
  return getUserToken();
});

ipcMain.handle('get-user-private', () => {
  return getUserPrivate();
});


ipcMain.handle('get-user-public', () => {
  return getUserPublic();
});

ipcMain.handle('get-user-id', () => {
  return getUserId();
});


ipcMain.on('open-add-friend-window', () => {
  const addFriendWindow = new BrowserWindow({
    width: 400,
    height: 300,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  addFriendWindow.loadFile(path.join(__dirname, './screens/add_friend.html'));
});


ipcMain.on('open-view-pending-friends-window', () => {
  const pendingFriendsWindow = new BrowserWindow({
    width: 400,
    height: 300,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  pendingFriendsWindow.loadFile(path.join(__dirname, './screens/view_pending_friends.html'));
});

ipcMain.on('open-view-friends-window', () => {
  const FriendsWindow = new BrowserWindow({
    width: 400,
    height: 300,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  FriendsWindow.loadFile(path.join(__dirname, './screens/view_friends.html'));
});



ipcMain.on('open-chatroom-window', (event, { friend, realFriendName, chatroomId, friendPublicKey, sk }) => {
  const chatroomWindow = new BrowserWindow({
    width: 750,
    height: 550,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  chatroomWindow.loadFile(path.join(__dirname, './screens/chatroom.html'));

  // Pass data to the chatroom window
  chatroomWindow.webContents.on('did-finish-load', () => {
    chatroomWindow.webContents.send('chatroom-data', { friend, realFriendName, chatroomId, friendPublicKey, sk });
  });
});


const createRootWindow = () => {
  const rootWindow = new BrowserWindow({
    width: 800,
    height: 600,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  rootWindow.loadFile(path.join(__dirname, './screens/root.html'));

}

const createWindow = () => {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.on('close', async () => {
    console.log("Closing app...");
  });

  mainWindow.on('closed', async () => {
    console.log("App fully closed.");
  });
};




 



  // Open the DevTools.
  // mainWindow.webContents.openDevTools();
ipcMain.on('save-json', (event, jsonData) => {
  fs.writeFile(path.join(__dirname, 'data.json'), jsonData, (err) => {
      if (err) {
          event.reply('save-json-response', 'Error saving file');
      } else {
          event.reply('save-json-response', 'File saved successfully');
      }
  });
});


// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.


function checkDatabase() {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(dbPath)) {
      return resolve(false);
    }

    let db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
      if (err) {
        return reject(err);
      }
    });

    db.get("SELECT token FROM main_user", (err, row) => {
      if (err) {
        db.close();
        return reject(err);
      }
      db.close();
      resolve(!!row);
    });
  });
}




checkDatabase().then(async isValid => {
  await startTor();


  // test
  // (async () => {
  //   let response = await torsend("https://api.ipify.org/", { method: "GET" });
  //   console.log("IP RESPONSE: " + JSON.stringify(response));
  // })();
  

  if (isValid) {
    app.whenReady().then(() => {
      createRootWindow();
    
      app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
          createRootWindow();
        }
      });
    });
  } else {
    app.whenReady().then(() => {
      createWindow();
    
      app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
          createWindow();
        }
      });
    });
  }
}).catch(err => {
  app.whenReady().then(() => {
    createWindow();
  
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  });
});






// actual app build /resources folder will contain the script
const scriptPath = path.join(process.resourcesPath, 'file_enc_dec.py');

// used for enc/dec files
function runPythonScript(data, key, iv,  operation) {
  return new Promise((resolve, reject) => {
      const pythonProcess = spawn('python3', [scriptPath]);

      // Prepare data to send to Python
      const input = JSON.stringify({ data, key, iv, operation });

      // Send data to Python script
      pythonProcess.stdin.write(input);
      pythonProcess.stdin.end();

      // Capture Python output
      let result = '';
      pythonProcess.stdout.on('data', (data) => {
          result += data.toString();
      });

      pythonProcess.stderr.on('data', (data) => {
          //console.error(`Error: ${data}`);
      });

      pythonProcess.on('close', () => {
          try {
              const output = JSON.parse(result);
              resolve(output.result);
          } catch (error) {
              reject(error);
          }
      });
  });
}

async function encryptData(data, key) {
  const encryptedData = await runPythonScript(data, key, "null", 'encrypt');
  //console.log("Encrypted Data:", encryptedData);
  return {
    ciphertext : encryptedData.ciphertext,
    iv : encryptedData.iv
  };
}

async function decryptData(encryptedData, key, iv) {
  const decryptedData = await runPythonScript(encryptedData, key, iv, 'decrypt');
  //console.log("Decrypted Data:", decryptedData);
  return decryptedData.decrypted_data;
}

ipcMain.handle('encrypt-data', async (event, data, key) => {
  return await encryptData(data, key);
});


ipcMain.handle('decrypt-data', async (event, encryptedData, key, iv) => {
  return await decryptData(encryptedData, key, iv);
});
