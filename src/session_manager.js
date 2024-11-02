const fs = require('fs');
const path = require('path');

// Define the file path for storing the token
const userDataPath = path.join(__dirname, 'user_data.json');

// Function to save the user data
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

// Function to retrieve the user data
function getUserData(callback) {
    fs.readFile(userDataPath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading user data:', err);
            callback(null); // return null if there was an error
            return;
        }
        try {
            const parsedData = JSON.parse(data);
            callback(parsedData); // Return the whole parsed data
        } catch (parseErr) {
            console.error('Error parsing user data:', parseErr);
            callback(null); // return null if parsing fails
        }
    });
}

module.exports = { saveUserData, getUserData };
