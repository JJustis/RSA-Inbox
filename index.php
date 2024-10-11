<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Secure Messaging Application with AES-256-GCM and HMAC Integrity Check">
    <title>Secure Messaging System</title>

    <!-- Bootstrap 5 CSS for UI styling -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Custom Styling -->
    <style>
        body { margin: 0; padding: 0; background-color: #f8f9fa; }
        .container { margin-top: 30px; }
        .content-section { margin-top: 20px; }
        .modal { overflow: hidden; }
    </style>
</head>
<body>
    <!-- Main Container -->
    <div class="container">
        <h1 class="text-center">Secure Messaging Application</h1>

        <!-- Section 1: Set Username and Generate Key Pair -->
        <div class="content-section">
            <h3>Set Username and Generate Key Pair</h3>
            <input type="text" id="username" class="form-control" placeholder="Enter your username" style="max-width: 400px;">
            <button id="setUsername" class="btn btn-primary mt-3">Set Username and Generate Key Pair</button>
            <div id="usernameMessage" class="alert alert-info mt-3 d-none"></div>
        </div>

        <!-- Section 2: Send Encrypted Message -->
        <div class="content-section">
            <h3>Send Encrypted Message</h3>
            <label for="recipient">Recipient Username</label>
            <input type="text" id="recipient" class="form-control mb-3" placeholder="Enter recipient username" style="max-width: 400px;">
            <textarea id="message" class="form-control" rows="4" placeholder="Enter your message here..." style="max-width: 600px;"></textarea>
            <button id="sendMessage" class="btn btn-success mt-3" disabled>Send Message</button>
            <div id="messageResponse" class="alert alert-info mt-3 d-none"></div>
        </div>

        <!-- Section 3: Public Key Roster -->
        <div class="content-section">
            <h3>Public Key Roster</h3>
            <ul id="publicKeyRoster" class="list-group" style="max-width: 600px;"></ul>
            <button id="refreshRoster" class="btn btn-secondary mt-3">Refresh Public Key Roster</button>
        </div>

        <!-- Section 4: Inbox -->
        <div class="content-section">
            <h3>Inbox</h3>
            <div id="inboxMessages" class="mt-3">
                <p class="text-muted">No messages yet.</p>
            </div>
        <button id="messagesButton" class="btn btn-primary">Fetch Messages</button>        </div>
    </div>

    <!-- Bootstrap 5 JS and Dependencies -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>

    <!-- CryptoJS Library -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>

    <!-- Main JavaScript Code -->
    <script>
        let privateKey, publicKey;


// Call fetchMessages when the button is clicked
document.getElementById('messagesButton').addEventListener('click', fetchMessages);
        // Function to set the username, generate key pair, and store in server
        document.getElementById('setUsername').addEventListener('click', async () => {
            const username = document.getElementById('username').value;
            if (!username) {
                alert("Please enter a username.");
                return;
            }

            try {
                // Generate RSA key pair for encryption and decryption
                const keyPair = await crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256"
                    },
                    true,
                    ["encrypt", "decrypt"]
                );

                privateKey = keyPair.privateKey;
                publicKey = await exportKey(keyPair.publicKey);

                // Send username and public key to server
                const response = await fetch('set_username.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, publicKey })
                });

                const data = await response.json();
                if (data.status === 'success') {
                    document.getElementById('usernameMessage').classList.remove('d-none');
                    document.getElementById('usernameMessage').classList.add('alert-success');
                    document.getElementById('usernameMessage').textContent = data.message;
                    document.getElementById('sendMessage').disabled = false;
                } else {
                    document.getElementById('usernameMessage').classList.remove('d-none');
                    document.getElementById('usernameMessage').classList.add('alert-danger');
                    document.getElementById('usernameMessage').textContent = data.message;
                }
            } catch (error) {
                console.error('Error generating key pair or setting username:', error);
            }
        });

        // Export the key as a Base64 string
        async function exportKey(key) {
            const exported = await crypto.subtle.exportKey("spki", key);
            return btoa(String.fromCharCode(...new Uint8Array(exported)));
        }

        // Function to send encrypted message to recipient
        document.getElementById('sendMessage').addEventListener('click', async () => {
            const recipient = document.getElementById('recipient').value;
            const message = document.getElementById('message').value;
            if (!recipient || !message) {
                alert("Please enter both recipient username and message.");
                return;
            }

            try {
                // Fetch recipient's public key
                const response = await fetch(`get_public_key.php?username=${recipient}`);
                const data = await response.json();

                if (data.status === 'success') {
                    const recipientPublicKey = await importPublicKey(data.publicKey);

                    // Encrypt the message using the recipient's public key
                    const encodedMessage = new TextEncoder().encode(message);
                    const encryptedMessage = await crypto.subtle.encrypt(
                        { name: "RSA-OAEP" },
                        recipientPublicKey,
                        encodedMessage
                    );

                    const encryptedMessageBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedMessage)));

                    // Send the encrypted message to the server
                    const sendMessageResponse = await fetch('send_message.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ recipient, message: encryptedMessageBase64 })
                    });

                    const sendMessageData = await sendMessageResponse.json();
                    if (sendMessageData.status === 'success') {
                        document.getElementById('messageResponse').classList.remove('d-none');
                        document.getElementById('messageResponse').classList.add('alert-success');
                        document.getElementById('messageResponse').textContent = 'Message sent successfully!';
                    } else {
                        document.getElementById('messageResponse').classList.remove('d-none');
                        document.getElementById('messageResponse').classList.add('alert-danger');
                        document.getElementById('messageResponse').textContent = sendMessageData.message;
                    }
                } else {
                    alert("Failed to fetch recipient's public key.");
                }
            } catch (error) {
                console.error("Error sending encrypted message:", error);
            }
        });

        // Function to import public key
        async function importPublicKey(pemKey) {
            const cleanedKey = pemKey.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\s)/g, '');
            const binaryDer = Uint8Array.from(atob(cleanedKey), c => c.charCodeAt(0));
            return await crypto.subtle.importKey("spki", binaryDer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
        }

        // Refresh Public Key Roster
        document.getElementById('refreshRoster').addEventListener('click', async () => {
            const response = await fetch('get_public_key_roster.php');
            const data = await response.json();
            const rosterElement = document.getElementById('publicKeyRoster');

            rosterElement.innerHTML = '';  // Clear the current roster

            if (data.status === 'success' && data.publicKeys) {
                data.publicKeys.forEach(entry => {
                    const listItem = document.createElement('li');
                    listItem.className = 'list-group-item';
                    listItem.textContent = `${entry.username}: ${entry.publicKey.substring(0, 40)}...`;
                    rosterElement.appendChild(listItem);
                });
            } else {
                rosterElement.innerHTML = '<li class="list-group-item">No public keys found.</li>';
            }
        });

        // Refresh Inbox
        document.getElementById('refreshInbox').addEventListener('click', async () => {
            const response = await fetch('get_inbox.php');
            const data = await response.json();
            const inboxMessages = document.getElementById('inboxMessages');

            inboxMessages.innerHTML = '';  // Clear existing messages
            if (data.status === 'success') {
                data.messages.forEach(msg => {
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'message';
                    messageDiv.innerHTML = `<strong>From: ${msg.sender}</strong><br>${msg.message}<br><small>${msg.timestamp}</small>`;
                    inboxMessages.appendChild(messageDiv);
                });
            } else {
                inboxMessages.innerHTML = '<p class="text-muted">No messages yet.</p>';
            }
        });

        // Refresh inbox and roster on page load
        window.onload = () => {
            document.getElementById('refreshRoster').click();
            document.getElementById('refreshInbox').click();
        };
		// Fetch the public key of the recipient
 async function getRecipientPublicKey(username) {
            try {
                // Fetch the public key from the server
                const response = await fetch(`get_public_key.php?username=${username}`);

                // Get the raw response text for debugging
                const rawText = await response.text();
                console.log("Raw Response:", rawText);  // Output the raw response for inspection

                // Parse the response as JSON (if valid)
                const data = JSON.parse(rawText);  // This line will throw an error if rawText is not valid JSON

                if (data.status === 'success') {
                    return data.publicKey;
                } else {
                    throw new Error(`Error fetching public key: ${data.message}`);
                }
            } catch (error) {
                console.error("Error fetching public key:", error);
                throw error;
            }
        }
async function sendEncryptedMessage(recipientId, recipientUsername, senderId, senderUsername, encryptedMessage) {
    try {
        const response = await fetch('send_message.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                recipient_id: recipientId,
                recipient_username: recipientUsername,
                sender_id: senderId,
                sender_username: senderUsername,
                message: encryptedMessage  // The encrypted message
            })
        });

        const rawText = await response.text();
        console.log("Raw Response from send_message.php:", rawText);

        const data = JSON.parse(rawText);

        if (data.status === 'success') {
            console.log('Message sent successfully!');
        } else {
            throw new Error(`Error sending message: ${data.message}`);
        }
    } catch (error) {
        console.error("Error sending encrypted message:", error);
        throw error;
    }
}
// Function to fetch messages and decrypt on the fly
async function fetchMessages() {
    try {
        const response = await fetch('get_inbox.php');
        
        // Log the raw response text before parsing it
        const rawText = await response.text();
        console.log("Raw Response from get_inbox.php:", rawText);

        // Attempt to parse the raw response as JSON
        const data = JSON.parse(rawText);

        if (data.status === 'success') {
            console.log('Messages fetched successfully!', data.messages);

            // Get the inboxMessages div element
            const inboxMessages = document.getElementById('inboxMessages');
            inboxMessages.innerHTML = '';  // Clear any previous content

            // Decrypt each message before displaying it
            for (const msg of data.messages) {
                try {
                    const decryptedMessage = await decryptMessage(msg.message);
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'message p-3 mb-2 border rounded';
                    messageDiv.innerHTML = `
                        <strong>From: ${msg.sender}</strong><br>
                        <p>Message: ${decryptedMessage}</p><br>
                        <small>Sent at: ${msg.timestamp}</small>
                    `;
                    inboxMessages.appendChild(messageDiv);
                } catch (decryptError) {
                    console.error("Failed to decrypt message:", decryptError);
                }
            }
        } else {
            throw new Error(`Error fetching messages: ${data.message}`);
        }
    } catch (error) {
        console.error("Error fetching messages:", error);
    }
}

// Function to decrypt the message using the private key
async function decryptMessage(encryptedMessageBase64) {
    try {
        // Decode the base64 encoded message to get the binary data
        const encryptedMessage = Uint8Array.from(atob(encryptedMessageBase64), c => c.charCodeAt(0));

        // Decrypt the message using the private key
        const decryptedMessageArrayBuffer = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedMessage
        );

        // Convert the decrypted message ArrayBuffer to a UTF-8 string
        const decryptedMessage = new TextDecoder().decode(decryptedMessageArrayBuffer);
        return decryptedMessage;
    } catch (error) {
        console.error("Decryption failed:", error);
        throw error;
    }
}



    </script>
</body>
</html>
