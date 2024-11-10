const fs = require('fs');
const path = require('path');

const userDataPath = path.join(__dirname, 'user_data.json');

function saveUserData(user_data, user_token) {
    console.log('Saving user data:', user_data, user_token); // Debug log
    const data = JSON.stringify({ user_data, user_token }, null, 2);
    fs.writeFile(userDataPath, data, (err) => {
        if (err) {
            console.error('Error saving user data:', err);
        } else {
            console.log('User data saved successfully.');
        }
    });
}

function getUserData(callback) {
    fs.readFile(userDataPath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading user data:', err);
            callback(null); 
            return;
        }
        try {
            const parsedData = JSON.parse(data);
            callback(parsedData);
        } catch (parseErr) {
            console.error('Error parsing user data:', parseErr);
            callback(null); 
        }
    });
}

module.exports = { saveUserData, getUserData };
