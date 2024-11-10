const { app, BrowserWindow,ipcMain } = require('electron');
const path = require('node:path');

const fs = require('fs');
const forge = require('node-forge');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const dbPath = path.join(__dirname, "data.db")

let db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log('Connected to the SQLite database.');
  }
});



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
        return console.error(err.message);
      }
      console.log(`A row has been inserted with rowid ${this.lastID}`);
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


// db.close((err) => {
//   if (err) {
//     console.error(err.message);
//   } else {
//     console.log('Close the database connection.');
//   }
// });



function checkForToken() {

}



// Function to get the username from data.json
// function getUserName() {
//   if (fs.existsSync(dataFilePath)) {
//     try {
//       const data = fs.readFileSync(dataFilePath, 'utf8');
//       const parsedData = JSON.parse(data);
//       if (parsedData.main_user && parsedData.main_user.user_data && parsedData.main_user.user_data.username) {
//         console.log('Username found:', parsedData.main_user.user_data.username);
//         return parsedData.main_user.user_data.username;
//       } else {
//         console.log('Username not found in data.json');
//         return null;
//       }
//     } catch (error) {
//       console.error('Error reading or parsing data.json:', error);
//       return null;
//     }
//   } else {
//     console.log('data.json does not exist');
//     return null;
//   }
// }



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

// Function to get the token from data.json
// function getUserToken() {
//   if (fs.existsSync(dataFilePath)) {
//     try {
//       const data = fs.readFileSync(dataFilePath, 'utf8');
//       const parsedData = JSON.parse(data);
//       if (parsedData.main_user && parsedData.main_user.token) {
//         console.log('Token found:', parsedData.main_user.token);
//         return parsedData.main_user.token;
//       } else {
//         console.log('Token not found in data.json');
//         return null;
//       }
//     } catch (error) {
//       console.error('Error reading or parsing data.json:', error);
//       return null;
//     }
//   } else {
//     console.log('data.json does not exist');
//     return null;
//   }
// }



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
  console.log("key", key)
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits) for AES-256 encryption.');
  }
  
  const iv = crypto.randomBytes(16); // Generate a random initialization vector (IV)

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return both the encrypted text and the IV, as the IV is needed for decryption
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
}

const ALGORITHM = 'aes-256-cbc';

function encryptFile(fileData, key) {
  // Generate a random initialization vector (IV)
  const iv = crypto.randomBytes(16);

  // Create a cipher instance with AES-256-CBC algorithm
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);

  // Encrypt the file data
  let encryptedData = cipher.update(Buffer.from(fileData));
  encryptedData = Buffer.concat([encryptedData, cipher.final()]);

  // Return the encrypted data and IV in Base64 format
  return {
    encryptedData: encryptedData.toString('base64'),
    iv: iv.toString('base64'),
  };
}

async function decryptFile(encryptedData, key, iv) {
  console.log("key", key);
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits) for AES-256 decryption.');
  }
  
  // Convert iv from hex back to a buffer
  const ivBuffer = Buffer.from(iv, 'hex');

  // Create a decipher with the same key and IV used for encryption
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuffer);

  // Decrypt the data
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// IPC handler for encryption
ipcMain.handle('encrypt-file', async (event, fileData, key) => {
  return encryptFile(fileData, key);
});


// IPC handler for decryption
ipcMain.handle('decrypt-file', async (event, encryptedData, key, iv) => {

  return decryptFile(encryptedData, key, iv);
  
});


ipcMain.handle('convert-arraybuffer-to-buffer', (event, arrayBuffer) => {
  // Convert the ArrayBuffer to a Buffer and return it
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

  // Validate that the key and IV have the correct lengths
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes (256 bits) for AES-256 decryption.');
  }
  if (iv.length !== 16) {
    throw new Error('IV must be 16 bytes for AES-256-CBC decryption.');
  }
  // Create a decipher instance
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  
  // Decrypt the data
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}



(async () => {
  const key = await generateSK(); // Generate or obtain a 32-byte symmetric key
  const keyHex = key.toString('hex');
  console.log('Generated Key:', keyHex);
  
  const result = await encryptMessageUsingSK('Hello, World!', key);
  console.log('Encrypted Text:', result.encryptedData);
  console.log('IV:', result.iv);


  const ivBuffer = Buffer.from(result.iv, 'hex'); // converts hex string to binary (buffer)
  console.log("ivBuffer", ivBuffer)
  const decryptedM = await decryptMessageUsingSK(result.encryptedData, key, ivBuffer)
  console.log("Decrypted text:", decryptedM)
})();


function encryptMessage(message, public_key){
  const encryptedMessage = crypto.publicEncrypt(public_key, Buffer.from(message));
  return encryptedMessage.toString('base64'); // binary to base64 (text) format (makes it easier to transport over the internet HTTP, JSON)  | proviedes compatbility between devices
}

function decryptMessage(encrypted_message, private_key){
  const encryptedMessageBuffer = Buffer.from(encrypted_message, "base64"); // takes a base64 encrypted text
  // Decrypt the message
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
  // Convert the signature from base64 to a buffer
  const signatureBuffer = Buffer.from(signature, 'base64');
  // Verify the signature
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





// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}


// Handle IPC messages to get the username
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


// Handle IPC message to open the "Add Friend" window
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
  // Create the browser window.
  const rootWindow = new BrowserWindow({
    width: 800,
    height: 600,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // and load the index.html of the app.
  rootWindow.loadFile(path.join(__dirname, './screens/root.html'));

}

const createWindow = () => {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // and load the index.html of the app.
  mainWindow.loadFile(path.join(__dirname, 'index.html'));


  // Listen for when the registration window is closed

  let isProgrammaticClose = false;

// if user clicks X
  mainWindow.on('close', (event) => {
    if (!isProgrammaticClose) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  function closeMainWindowProgrammatically() {
    isProgrammaticClose = true;
    mainWindow.close();
  }

mainWindow.on('closed', async () => {
    const rootWindow = new BrowserWindow({
      width: 800,
      height: 600,
      resizable: false,
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
      },
    });
  
    rootWindow.loadFile(path.join(__dirname, './screens/root.html'));
});




 



  // Open the DevTools.
  // mainWindow.webContents.openDevTools();
};

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

checkDatabase().then(isValid => {
  if (isValid) {
    app.whenReady().then(() => {
      createRootWindow();
    
      // On OS X it's common to re-create a window in the app when the
      // dock icon is clicked and there are no other windows open.
      app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
          createRootWindow();
        }
      });
    });
  } else {
    app.whenReady().then(() => {
      createWindow();
    
      // On OS X it's common to re-create a window in the app when the
      // dock icon is clicked and there are no other windows open.
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
  
    // On OS X it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  });
});



// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and import them here.

const { spawn } = require('child_process');

function runPythonScript(data, key, iv,  operation) {
  return new Promise((resolve, reject) => {
      const pythonProcess = spawn('python3', ['src/main.py']);

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
          console.error(`Error: ${data}`);
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
  console.log("Encrypted Data:", encryptedData);
  return {
    ciphertext : encryptedData.ciphertext,
    iv : encryptedData.iv
  };
}

// Decrypt data
async function decryptData(encryptedData, key, iv) {
  const decryptedData = await runPythonScript(encryptedData, key, iv, 'decrypt');
  console.log("Decrypted Data:", decryptedData);
  return decryptedData.decrypted_data;
}

ipcMain.handle('encrypt-data', async (event, data, key) => {
  return await encryptData(data, key);
});


ipcMain.handle('decrypt-data', async (event, encryptedData, key, iv) => {
  return await decryptData(encryptedData, key, iv);
});