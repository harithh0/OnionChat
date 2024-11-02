// import { API_URL } from "./config";

export async function registerUser(username, password) {
    const url = `http://127.0.0.1:8000/api/register/`;
    const body = { "username": username, "password": password };

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            throw new Error(`Error: ${response.status} ${response.statusText}`);
        }

        return await response.json(); // Parse the response as JSON
    } catch (error) {
        console.error("Request failed:", error);
        throw error; // Re-throw the error for further handling
    }
}
